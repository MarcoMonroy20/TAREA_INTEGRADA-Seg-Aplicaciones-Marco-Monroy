"""Pruebas reproducibles y evidencias del laboratorio con datos sintéticos."""

import base64
from contextlib import closing
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import zipfile

from cryptography.exceptions import InvalidTag
from werkzeug.serving import make_server

from app import crear_app, inicializar_base
from ejecutar import SolicitudSinDatosSensibles
from preparar import preparar_certificados
from seguridad import (KDF, cifrar_expediente, descifrar_expediente,
                       validar_busqueda, validar_carnet, validar_correo,
                       validar_nombre, validar_nota, verificar_password)

RAIZ = Path(__file__).resolve().parent
EVIDENCIAS = RAIZ / "evidencias"
TEMPORALES = RAIZ / ".pruebas_temporales"
BASE = "https://localhost"
PASSWORD = "CuentaFicticia-2026!"
DETALLES = {}


class AnalizadorHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1


class ControlesDelPortal(unittest.TestCase):
    def setUp(self):
        TEMPORALES.mkdir(parents=True, exist_ok=True)
        self.temporal = tempfile.TemporaryDirectory(prefix="portal_pruebas_", dir=TEMPORALES)
        self.ruta = Path(self.temporal.name)
        self.clave = secrets.token_bytes(32)
        self.app = crear_app({
            "TESTING": True,
            "SECRET_KEY": secrets.token_urlsafe(48),
            "DATA_KEY": base64.b64encode(self.clave).decode("ascii"),
            "DATABASE": str(self.ruta / "portal.sqlite3"),
            "AUDIT_LOG": str(self.ruta / "seguridad.jsonl"),
        })
        inicializar_base(self.app, PASSWORD)
        self.cliente = self.app.test_client()

    def tearDown(self):
        self.app.registro.close()
        self.temporal.cleanup()

    def get(self, ruta):
        return self.cliente.get(ruta, base_url=BASE)

    def token(self, ruta="/login"):
        respuesta = self.get(ruta)
        coincidencia = re.search(r'name="csrf_token" value="([^"]+)"', respuesta.get_data(as_text=True))
        self.assertIsNotNone(coincidencia)
        return coincidencia.group(1)

    def post(self, ruta, datos, origen="/login"):
        valores = {**datos, "csrf_token": self.token(origen)}
        return self.cliente.post(ruta, data=valores, base_url=BASE)

    def login(self, correo="admin@example.invalid"):
        respuesta = self.post("/login", {"correo": correo, "password": PASSWORD})
        self.assertEqual(respuesta.status_code, 302)
        return respuesta

    def filas(self, sql, parametros=()):
        with closing(sqlite3.connect(self.app.config["DATABASE"])) as db:
            return db.execute(sql, parametros).fetchall()

    def logs(self):
        return [json.loads(linea) for linea in Path(self.app.config["AUDIT_LOG"]).read_text(encoding="utf-8").splitlines()]

    def test_01_validaciones_y_normalizacion(self):
        self.assertEqual(validar_nombre("  Mari\u0301a   José "), "María José")
        self.assertEqual(validar_nombre("O'Neill"), "O'Neill")
        self.assertEqual(validar_correo(" ANA@EXAMPLE.INVALID "), "ana@example.invalid")
        self.assertEqual(validar_carnet("masi-0003"), "MASI-0003")
        self.assertEqual(validar_nota("99.25"), "99.25")
        for funcion, entrada in [(validar_nombre, "<script>"), (validar_nombre, "=SUM(A1)"),
                                 (validar_correo, "ana@@example.invalid"),
                                 (validar_correo, "a..b@example.invalid"),
                                 (validar_carnet, "../0001"), (validar_nota, "NaN"),
                                 (validar_nota, "101"), (validar_nota, "-1"),
                                 (validar_nota, "10.001"), (validar_busqueda, "A" * 81),
                                 (validar_busqueda, "hola\r\nfalso")]:
            with self.subTest(entrada=entrada), self.assertRaises(ValueError):
                funcion(entrada)
        DETALLES["validacion"] = {"normalizacion_unicode": True, "rangos_y_formatos": True,
                                  "busqueda_con_apostrofos_permitida": validar_busqueda("O'Neill") == "O'Neill"}

    def test_02_sql_vulnerable_y_corregido(self):
        entrada = "' OR 1=1 --"
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE estudiantes (nombre TEXT)")
            db.executemany("INSERT INTO estudiantes VALUES (?)", [("Ana",), ("Luis",)])
            sql_vulnerable = f"SELECT nombre FROM estudiantes WHERE nombre = '{entrada}'"
            antes = db.execute(sql_vulnerable).fetchall()
            despues = db.execute("SELECT nombre FROM estudiantes WHERE nombre = ?", (entrada,)).fetchall()
        self.assertEqual(len(antes), 2)
        self.assertEqual(despues, [])
        self.login()
        respuesta = self.get("/estudiantes?" + urlencode({"q": entrada}))
        self.assertEqual(respuesta.status_code, 200)
        self.assertIn("No se encontraron estudiantes", respuesta.get_data(as_text=True))
        self.assertNotIn("<td>MASI-0001</td>", respuesta.get_data(as_text=True))
        DETALLES["sql"] = {"entrada": entrada, "consulta_vulnerable": sql_vulnerable,
                           "filas_vulnerable": len(antes), "filas_parametrizada": len(despues),
                           "portal_corregido_http": respuesta.status_code,
                           "causa": "Concatenar datos dentro de la instrucción SQL"}

    def test_03_busqueda_legitima(self):
        self.login()
        respuesta = self.get("/estudiantes?q=Ana")
        self.assertIn("MASI-0001", respuesta.get_data(as_text=True))
        self.assertNotIn("MASI-0002", respuesta.get_data(as_text=True))
        respuesta = self.get("/estudiantes?q=%25")
        self.assertIn("No se encontraron estudiantes", respuesta.get_data(as_text=True))

    def test_04_xss_almacenado_y_reflejado(self):
        self.login()
        entrada = "<script>alert('prueba')</script>"
        respuesta = self.post("/comentarios", {"comentario": entrada}, "/comentarios")
        self.assertEqual(respuesta.status_code, 302)
        self.assertEqual(self.filas("SELECT texto FROM comentarios")[0][0], entrada)
        pagina = self.get("/comentarios").get_data(as_text=True)
        self.assertIn("&lt;script&gt;", pagina)
        analizador = AnalizadorHTML()
        analizador.feed(pagina)
        self.assertEqual(analizador.scripts, 0)
        reflejada = self.get("/estudiantes?" + urlencode({"q": entrada})).get_data(as_text=True)
        self.assertNotIn(entrada, reflejada)
        self.assertIn("&lt;script&gt;", reflejada)
        DETALLES["xss"] = {"entrada": entrada, "guardada_como_dato": True,
                           "salida_codificada": True, "etiquetas_script_activas": analizador.scripts,
                           "reflejado_codificado": True, "uso_de_innerHTML": False,
                           "salida_html_observada": re.search(r'<p class="texto-comentario">(.*?)</p>', pagina, re.S).group(1)}

    def test_05_reportes_sin_shell(self):
        self.login()
        with patch("subprocess.run", side_effect=AssertionError("El portal no debe ejecutar comandos")):
            correcto = self.post("/reportes/descargar", {"formato": "zip"}, "/reportes")
            malicioso = self.post("/reportes/descargar", {"formato": "zip; echo INYECTADO"}, "/reportes")
        self.assertEqual(correcto.status_code, 200)
        self.assertEqual(malicioso.status_code, 400)
        with zipfile.ZipFile(io.BytesIO(correcto.data)) as archivo:
            self.assertEqual(archivo.namelist(), ["estudiantes.csv"])
            self.assertIn("MASI-0001", archivo.read("estudiantes.csv").decode("utf-8-sig"))
        DETALLES["comandos"] = {"implementacion": "zipfile.ZipFile en memoria",
                                "shell_ejecutado": False, "formato_malicioso_http": 400,
                                "zip_valido": True, "nombre_de_archivo_controlado": "estudiantes.csv"}

    def test_06_argon2id_y_sal(self):
        primero = KDF.hash(PASSWORD)
        segundo = KDF.hash(PASSWORD)
        guardado = self.filas("SELECT password_hash FROM usuarios LIMIT 1")[0][0]
        self.assertNotEqual(primero, segundo)
        self.assertTrue(guardado.startswith("$argon2id$v=19$m=19456,t=2,p=1$"))
        self.assertNotIn(PASSWORD, guardado)
        self.assertTrue(verificar_password(guardado, PASSWORD))
        self.assertFalse(verificar_password(guardado, "ContraseñaIncorrecta"))
        self.assertTrue(verificar_password(primero, PASSWORD))
        self.assertTrue(verificar_password(segundo, PASSWORD))
        DETALLES["passwords"] = {"hash_de_cuenta_ficticia": guardado,
                                 "primer_hash_misma_password": primero,
                                 "segundo_hash_misma_password": segundo,
                                 "primera_sal": primero.split("$")[4],
                                 "segunda_sal": segundo.split("$")[4],
                                 "sal_aleatoria_hashes_distintos": primero != segundo,
                                 "password_correcta_aceptada": True,
                                 "password_incorrecta_rechazada": True}

    def test_07_login_incorrecto_y_logging(self):
        password = "NO_REGISTRAR_ESTA_PASSWORD_123"
        respuesta = self.post("/login", {"correo": "admin@example.invalid", "password": password})
        self.assertEqual(respuesta.status_code, 401)
        registros = self.logs()
        self.assertEqual(registros[-1]["evento"], "login_fallido")
        texto_log = Path(self.app.config["AUDIT_LOG"]).read_text(encoding="utf-8")
        self.assertNotIn(password, texto_log)
        self.assertNotIn("admin@example.invalid", texto_log)
        self.assertIn("Credenciales incorrectas", respuesta.get_data(as_text=True))
        with self.cliente.session_transaction(base_url=BASE) as sesion:
            self.assertNotIn("uid", sesion)
        DETALLES["login_fallido"] = {"http": 401, "registro": registros[-1],
                                     "password_en_log": False, "correo_en_log": False,
                                     "mensaje_observado": "Credenciales incorrectas.",
                                     "sesion_autenticada": False}

    def test_08_cifrado_integridad_y_vinculacion(self):
        datos = {"nota": "83.25", "observacion": "INFORMACION_SENSIBLE_FICTICIA"}
        primero = cifrar_expediente(self.clave, 1, datos)
        segundo = cifrar_expediente(self.clave, 1, datos)
        self.assertNotEqual(primero, segundo)
        self.assertNotIn(datos["observacion"], primero)
        self.assertEqual(descifrar_expediente(self.clave, 1, primero), datos)
        alterado = bytearray(base64.b64decode(primero))
        alterado[-1] ^= 1
        with self.assertRaises(InvalidTag):
            descifrar_expediente(self.clave, 1, base64.b64encode(alterado).decode("ascii"))
        with self.assertRaises(InvalidTag):
            descifrar_expediente(self.clave, 2, primero)
        almacenado = self.filas("SELECT expediente FROM estudiantes WHERE id = 1")[0][0]
        self.assertNotIn("Expediente académico ficticio", almacenado)
        DETALLES["cifrado"] = {"algoritmo": "AES-256-GCM", "nonce_bytes": 12,
                               "tag_bytes": 16, "nonce_distinto": True,
                               "alteracion_rechazada": True, "intercambio_entre_expedientes_rechazado": True,
                               "cifrado_ficticio_muestra": almacenado}

    def test_09_secretos_externos_y_fallo_sin_claves(self):
        secreto = secrets.token_urlsafe(48)
        clave = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        with patch.dict(os.environ, {"PORTAL_SESSION_SECRET": secreto, "PORTAL_DATA_KEY": clave}, clear=True):
            externa = crear_app({"DATABASE": str(self.ruta / "otra.sqlite3"), "AUDIT_LOG": str(self.ruta / "otra.jsonl")})
            try:
                self.assertEqual(externa.secret_key, secreto)
                self.assertEqual(externa.clave_datos, base64.b64decode(clave))
                huella_externa = hashlib.sha256(base64.b64decode(clave)).hexdigest()
                huella_consumida = hashlib.sha256(externa.clave_datos).hexdigest()
            finally:
                externa.registro.close()
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError) as error_configuracion:
            crear_app()
        DETALLES["secretos"] = {"fuente": "variables de entorno",
                                "clave_de_sesion_utilizada": True, "clave_de_cifrado_utilizada": True,
                                "inicio_sin_secretos_rechazado": True, "valor_del_secreto": "omitido",
                                "huella_sha256_clave_externa_ficticia": huella_externa,
                                "huella_sha256_clave_consumida": huella_consumida,
                                "error_sin_configuracion": str(error_configuracion.exception)}

    def test_10_tls_real_con_validacion(self):
        preparar_certificados(self.ruta)
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexto.minimum_version = ssl.TLSVersion.TLSv1_2
        contexto.load_cert_chain(self.ruta / "servidor.crt", self.ruta / "servidor.key")
        servidor = make_server("127.0.0.1", 8444, self.app, threaded=True,
                              ssl_context=contexto, request_handler=SolicitudSinDatosSensibles)
        hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
        hilo.start()
        try:
            cliente = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cliente.load_verify_locations(cafile=str(self.ruta / "ca.crt"))
            with socket.create_connection(("127.0.0.1", servidor.server_port)) as conexion:
                with cliente.wrap_socket(conexion, server_hostname="127.0.0.1") as tls:
                    protocolo = tls.version()
                    cifrado = tls.cipher()[0]
                    tls.sendall(b"GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    respuesta = b""
                    while bloque := tls.recv(65536):
                        respuesta += bloque
            self.assertIn(b"200 OK", respuesta)
            self.assertIn(protocolo, ("TLSv1.2", "TLSv1.3"))
            with self.assertRaises(ssl.SSLCertVerificationError):
                with socket.create_connection(("127.0.0.1", servidor.server_port)) as conexion:
                    with cliente.wrap_socket(conexion, server_hostname="sitio-ajeno.invalid"):
                        pass
            DETALLES["tls"] = {"conexion_real": True, "protocolo": protocolo,
                               "suite": cifrado, "certificado_validado_con_ca_local": True,
                               "nombre_o_ip_verificado": "127.0.0.1", "hostname_incorrecto_rechazado": True,
                               "respuesta": respuesta.split(b"\r\n", 1)[0].decode("ascii")}
        except ssl.SSLCertVerificationError as error:
            DETALLES["tls_red"] = {
                "estado": "PENDIENTE POR INTERFERENCIA DEL ENTORNO",
                "validacion_del_certificado": "RECHAZADA",
                "motivo": error.verify_message,
                "nota": "La inspección HTTPS local puede sustituir el certificado. No se desactivó la validación."}
            self.skipTest("La conexión local no valida la CA del laboratorio; revisar inspección HTTPS del equipo.")
        finally:
            servidor.shutdown()
            servidor.server_close()
            hilo.join(timeout=5)

    def test_21_tls_canal_autenticado_en_memoria(self):
        preparar_certificados(self.ruta)
        servidor_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        servidor_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        servidor_ctx.load_cert_chain(self.ruta / "servidor.crt", self.ruta / "servidor.key")
        cliente_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cliente_ctx.load_verify_locations(cafile=str(self.ruta / "ca.crt"))
        entrada_cliente, salida_cliente = ssl.MemoryBIO(), ssl.MemoryBIO()
        entrada_servidor, salida_servidor = ssl.MemoryBIO(), ssl.MemoryBIO()
        cliente = cliente_ctx.wrap_bio(entrada_cliente, salida_cliente, server_hostname="localhost")
        servidor = servidor_ctx.wrap_bio(entrada_servidor, salida_servidor, server_side=True)
        cliente_listo = servidor_listo = False
        for _ in range(30):
            if not cliente_listo:
                try:
                    cliente.do_handshake()
                    cliente_listo = True
                except ssl.SSLWantReadError:
                    pass
            if salida_cliente.pending:
                entrada_servidor.write(salida_cliente.read())
            if not servidor_listo:
                try:
                    servidor.do_handshake()
                    servidor_listo = True
                except ssl.SSLWantReadError:
                    pass
            if salida_servidor.pending:
                entrada_cliente.write(salida_servidor.read())
            if cliente_listo and servidor_listo:
                break
        self.assertTrue(cliente_listo and servidor_listo)
        solicitud = b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cliente.write(solicitud)
        transmitido = salida_cliente.read()
        self.assertNotIn(b"GET /login", transmitido)
        entrada_servidor.write(transmitido)
        self.assertEqual(servidor.read(), solicitud)
        servidor.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        entrada_cliente.write(salida_servidor.read())
        self.assertIn(b"200 OK", cliente.read())
        DETALLES["tls_memoria"] = {
            "estado": "APROBADA", "protocolo": cliente.version(), "suite": cliente.cipher()[0],
            "ca_local_y_nombre_verificados": True, "certificado_verificado": cliente.getpeercert()["subjectAltName"],
            "datos_http_cifrados": True,
            "alcance": "Canal TLS de OpenSSL con MemoryBIO; no acredita la conexión de red del navegador"}

    def test_11_error_interno_sin_secretos(self):
        centinela = "CLAVE_INTERNA_NO_PUBLICAR_2026"

        @self.app.get("/solo-prueba-error")
        def error_controlado():
            raise RuntimeError(centinela)

        respuesta = self.get("/solo-prueba-error")
        self.assertEqual(respuesta.status_code, 500)
        self.assertNotIn(centinela, respuesta.get_data(as_text=True))
        self.assertNotIn(centinela, Path(self.app.config["AUDIT_LOG"]).read_text(encoding="utf-8"))
        self.assertNotIn("Traceback", respuesta.get_data(as_text=True))
        mensaje_observado = re.search(r'<h1>(.*?)</h1>', respuesta.get_data(as_text=True), re.S).group(1)
        DETALLES["errores"] = {"http": 500, "mensaje_generico": True,
                               "mensaje_observado": mensaje_observado,
                               "secreto_en_respuesta": False, "secreto_en_log": False,
                               "registro": self.logs()[-1]}

    def test_12_estudiante_no_ve_expediente_ajeno(self):
        self.login("ana@example.invalid")
        self.assertEqual(self.get("/expediente/1").status_code, 200)
        self.assertEqual(self.get("/expediente/2").status_code, 403)
        self.assertEqual(self.get("/estudiantes").status_code, 403)
        self.assertEqual(self.get("/reportes").status_code, 403)
        self.assertEqual(self.get("/administracion").status_code, 403)
        DETALLES["autorizacion"] = {"expediente_propio": 200, "expediente_ajeno": 403,
                                    "listado_reportes_administracion_para_estudiante": 403}

    def test_13_modificacion_y_eventos(self):
        self.login()
        self.get("/expediente/1")
        respuesta = self.post("/expediente/1", {"nota": "94.50", "observacion": "Prueba académica"}, "/expediente/1")
        self.assertEqual(respuesta.status_code, 302)
        self.assertIn("94.50", self.get("/expediente/1").get_data(as_text=True))
        self.get("/administracion")
        eventos = [r["evento"] for r in self.logs()]
        for evento in ("login_correcto", "expediente_consultado", "expediente_modificado", "acceso_administrativo"):
            self.assertIn(evento, eventos)
        permitidos = {"fecha_utc", "evento", "actor_id", "objeto_id", "resultado", "solicitud_id"}
        self.assertTrue(all(set(registro) == permitidos for registro in self.logs()))
        DETALLES["logging"] = {"registros": self.logs(), "campos_limitados": True,
                               "passwords_tokens_claves_y_datos_personales_en_registros": False}

    def test_14_csrf_y_cookies(self):
        respuesta = self.get("/login")
        cookie = respuesta.headers.get("Set-Cookie", "")
        for atributo in ("Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(atributo, cookie)
        incorrecto = self.cliente.post("/login", base_url=BASE, data={"correo": "admin@example.invalid", "password": PASSWORD})
        self.assertEqual(incorrecto.status_code, 400)
        unicode_invalido = self.cliente.post("/login", base_url=BASE, data={"csrf_token": "é"})
        self.assertEqual(unicode_invalido.status_code, 400)
        self.assertIn("script-src 'none'", respuesta.headers["Content-Security-Policy"])
        DETALLES["sesiones"] = {"cookie_secure": True, "cookie_httponly": True,
                                "samesite": "Lax", "csrf_ausente_http": 400,
                                "csp_scripts_bloqueados": True}

    def test_15_rechazo_de_http_y_host_ajeno(self):
        self.assertEqual(self.cliente.get("/login", base_url="http://localhost").status_code, 400)
        self.assertEqual(self.cliente.get("/login", base_url="https://host-ajeno.invalid").status_code, 400)

    def test_16_bloqueo_temporal(self):
        password_incorrecta = secrets.token_urlsafe(24)
        for _ in range(5):
            respuesta = self.post("/login", {"correo": "admin@example.invalid", "password": password_incorrecta})
            self.assertEqual(respuesta.status_code, 401)
        bloqueado = self.post("/login", {"correo": "admin@example.invalid", "password": PASSWORD})
        self.assertEqual(bloqueado.status_code, 429)
        DETALLES["bloqueo"] = {"fallos_previos": 5, "http_posterior": 429, "duracion_segundos": 60}

    def test_17_registro_y_duplicados(self):
        datos = {"correo": "maria@example.invalid", "nombre": "María", "apellido": "O'Neill",
                 "carnet": "MASI-0003", "password": PASSWORD}
        self.assertEqual(self.post("/registro", datos, "/registro").status_code, 302)
        self.assertEqual(self.post("/registro", datos, "/registro").status_code, 409)
        self.assertEqual(len(self.filas("SELECT id FROM estudiantes WHERE carnet = ?", ("MASI-0003",))), 1)
        self.login("maria@example.invalid")
        self.assertEqual(self.get("/expediente/3").status_code, 200)

    def test_18_nota_invalida_no_modifica(self):
        self.login()
        antes = self.filas("SELECT expediente FROM estudiantes WHERE id = 1")[0][0]
        self.assertEqual(self.post("/expediente/1", {"nota": "NaN", "observacion": "Prueba"}, "/expediente/1").status_code, 400)
        self.assertEqual(antes, self.filas("SELECT expediente FROM estudiantes WHERE id = 1")[0][0])

    def test_19_fallo_de_logging_rechaza_operacion(self):
        self.login()
        with patch.object(self.app.registro, "handle", side_effect=OSError("Fallo de disco ficticio")):
            respuesta = self.get("/administracion")
        self.assertEqual(respuesta.status_code, 503)
        self.assertNotIn("Fallo de disco", respuesta.get_data(as_text=True))
        self.post("/logout", {}, "/")
        token = self.token()
        with patch.object(self.app.registro, "handle", side_effect=OSError("Fallo ficticio")):
            respuesta = self.cliente.post("/login", base_url=BASE, data={
                "correo": "admin@example.invalid", "password": PASSWORD, "csrf_token": token})
        self.assertEqual(respuesta.status_code, 503)
        with self.cliente.session_transaction(base_url=BASE) as sesion:
            self.assertNotIn("uid", sesion)


class SecretosEnGit(unittest.TestCase):
    def test_20_credencial_borrada_permanece_en_historial(self):
        herramienta = os.environ.get("GITLEAKS_BIN") or str(RAIZ / ".herramientas" / "gitleaks.exe")
        self.assertTrue(Path(herramienta).is_file() or shutil.which(herramienta), "Instale Gitleaks o defina GITLEAKS_BIN. No se simula la detección.")
        TEMPORALES.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="git_ficticio_", dir=TEMPORALES) as temporal:
            repo = Path(temporal)

            def git(*argumentos):
                proceso = subprocess.run(["git", "-c", "user.name=Laboratorio", "-c", "user.email=laboratorio@example.invalid",
                                           *argumentos], cwd=repo, check=True, capture_output=True, text=True)
                return proceso.stdout.strip()

            git("init", "--initial-branch=main")
            credencial = "masi_demo_" + secrets.token_hex(16)
            ruta = repo / "config_ficticia.py"
            ruta.write_text(f'CLAVE_SERVICIO = "{credencial}"\n', encoding="utf-8")
            git("add", "config_ficticia.py")
            git("commit", "-m", "Agregar configuración ficticia del laboratorio")
            commit_expuesto = git("rev-parse", "HEAD")
            ruta.write_text('import os\nCLAVE_SERVICIO = os.environ.get("CLAVE_SERVICIO")\n', encoding="utf-8")
            git("add", "config_ficticia.py")
            git("commit", "-m", "Retirar la credencial ficticia del código actual")
            reporte = EVIDENCIAS / "gitleaks_historial.json"
            comando = [herramienta, "git", str(repo), "--config", str(RAIZ / ".gitleaks.toml"),
                       "--report-format", "json", "--report-path", str(reporte), "--redact", "--no-banner"]
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=60)
            self.assertEqual(proceso.returncode, 1, proceso.stderr)
            hallazgos = json.loads(reporte.read_text(encoding="utf-8"))
            self.assertTrue(any(h["RuleID"] == "credencial-ficticia-masi" and h["Commit"] == commit_expuesto for h in hallazgos))
            self.assertNotIn(credencial, ruta.read_text(encoding="utf-8"))
            version = subprocess.run([herramienta, "version"], capture_output=True, text=True, check=True).stdout.strip()
            salida = re.sub(r"[\x1b\x9b]\[[0-?]*[ -/]*[@-~]", "", proceso.stdout + proceso.stderr)
            salida = salida.replace(str(repo), "REPOSITORIO_FICTICIO")
            (EVIDENCIAS / "gitleaks_salida.txt").write_text(salida, encoding="utf-8")
            (EVIDENCIAS / "git_historial.txt").write_text(git("log", "--oneline") + "\n", encoding="utf-8")
            DETALLES["git"] = {"herramienta": "Gitleaks", "version": version,
                               "codigo_salida": proceso.returncode, "hallazgos": len(hallazgos),
                               "regla": "credencial-ficticia-masi", "commit_expuesto": commit_expuesto,
                               "secreto_ausente_del_archivo_actual": True,
                               "secreto_detectado_en_historial": True, "credencial_sintetica": True,
                               "verificacion_de_validez_en_servicio_externo": "No aplica; credencial ficticia"}


class ResultadoConEvidencias(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.casos = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.casos.append({"prueba": test._testMethodName, "estado": "APROBADA"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.casos.append({"prueba": test._testMethodName, "estado": "FALLIDA"})

    def addError(self, test, err):
        super().addError(test, err)
        self.casos.append({"prueba": test._testMethodName, "estado": "ERROR"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.casos.append({"prueba": test._testMethodName, "estado": "PENDIENTE", "motivo": reason})


def main():
    EVIDENCIAS.mkdir(exist_ok=True)
    flujo = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    resultado = unittest.TextTestRunner(stream=flujo, verbosity=2, resultclass=ResultadoConEvidencias).run(suite)
    texto = flujo.getvalue()
    print(texto)
    (EVIDENCIAS / "ejecucion_pruebas.txt").write_text(texto, encoding="utf-8")
    resumen = {"fecha_utc": datetime.now(timezone.utc).isoformat(),
               "total": resultado.testsRun, "fallos": len(resultado.failures),
               "errores": len(resultado.errors), "omitidas": len(resultado.skipped),
               "casos": resultado.casos, "detalles": DETALLES}
    (EVIDENCIAS / "resultados_pruebas.json").write_text(json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8")
    if resultado.skipped:
        print("Hay comprobaciones pendientes. Consulte resultados_pruebas.json antes de declarar cumplimiento completo.")
    raise SystemExit(1 if not resultado.wasSuccessful() else (2 if resultado.skipped else 0))


if __name__ == "__main__":
    main()
