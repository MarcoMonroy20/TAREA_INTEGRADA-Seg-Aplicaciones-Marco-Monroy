"""Presenta los resultados registrados para su revisión y captura en el navegador."""

from pathlib import Path
import hashlib
from html import escape
import json

RAIZ = Path(__file__).resolve().parent
EVIDENCIAS = RAIZ / "evidencias"


def pre(valor):
    texto = json.dumps(valor, indent=2, ensure_ascii=False) if not isinstance(valor, str) else valor
    return "<pre>" + escape(texto) + "</pre>"


def tabla(filas):
    return '<table><tbody>' + ''.join(
        '<tr><th scope="row">' + escape(str(clave)) + '</th><td>' + escape(str(valor)) + '</td></tr>'
        for clave, valor in filas) + '</tbody></table>'


def generar():
    archivo = EVIDENCIAS / "resultados_pruebas.json"
    datos_crudos = archivo.read_bytes()
    resultados = json.loads(datos_crudos)
    if resultados["fallos"] or resultados["errores"] or resultados["omitidas"]:
        raise ValueError("Complete las pruebas antes de preparar las evidencias de entrega.")
    d = resultados["detalles"]
    hallazgos = json.loads((EVIDENCIAS / "gitleaks_historial.json").read_text(encoding="utf-8"))
    if not hallazgos:
        raise ValueError("Falta el hallazgo real de Gitleaks del ejercicio ficticio.")
    hallazgo = {k: hallazgos[0][k] for k in ("RuleID", "File", "Commit", "Match", "Secret")}
    kdf = d["passwords"]
    secreto = d["secretos"]
    login = d["login_fallido"]
    error = d["errores"]
    casos = [
        ("01_sql", "Entrada con caracteres especiales en búsqueda", "No altera la estructura SQL.", "02 y 03",
         '<h2>Entrada enviada</h2>' + pre(d["sql"]["entrada"]) +
         tabla([("Consulta vulnerable controlada", f'{d["sql"]["filas_vulnerable"]} filas'),
                ("Consulta parametrizada", f'{d["sql"]["filas_parametrizada"]} filas'),
                ("Portal corregido", f'HTTP {d["sql"]["portal_corregido_http"]}; búsqueda sin resultados indebidos')]) +
         '<h2>Consulta vulnerable reproducida</h2>' + pre(d["sql"]["consulta_vulnerable"])),
        ("02_xss", "Comentario con contenido HTML", "No se ejecuta como contenido activo.", "04",
         '<h2>Comentario publicado</h2>' + pre(d["xss"]["entrada"]) +
         '<h2>HTML observado en la respuesta</h2>' + pre(d["xss"]["salida_html_observada"]) +
         tabla([("Conservado como dato en la base", "Sí" if d["xss"]["guardada_como_dato"] else "No"),
                ("Etiquetas script activas", d["xss"]["etiquetas_script_activas"]),
                ("Salida reflejada también codificada", "Sí" if d["xss"]["reflejado_codificado"] else "No")])),
        ("03_kdf", "Contraseña almacenada", "Se conserva mediante una KDF con sal.", "06",
         '<h2>Valor consultado en usuarios.password_hash</h2>' + pre(kdf["hash_de_cuenta_ficticia"]) +
         tabla([("Algoritmo y parámetros", "Argon2id; m=19456 KiB, t=2, p=1"),
                ("Sal de la primera derivación", kdf["primera_sal"]),
                ("Sal de la segunda derivación", kdf["segunda_sal"]),
                ("Misma contraseña, hashes diferentes", "Sí" if kdf["sal_aleatoria_hashes_distintos"] else "No"),
                ("Verificación de la contraseña correcta", "Aceptada" if kdf["password_correcta_aceptada"] else "Rechazada")]) +
         '<p class="aclaracion">El hash y las sales corresponden únicamente a cuentas ficticias de las pruebas. La contraseña no se publica.</p>'),
        ("04_password_incorrecta", "Contraseña incorrecta", "Se rechaza la autenticación.", "07",
         tabla([("Solicitud de prueba", "POST /login con una contraseña ficticia incorrecta"),
                ("Respuesta observada", f'HTTP {login["http"]}'),
                ("Mensaje al usuario", login["mensaje_observado"]),
                ("Sesión autenticada creada", "Sí" if login["sesion_autenticada"] else "No"),
                ("Contraseña incorrecta rechazada por la KDF", "Sí" if kdf["password_incorrecta_rechazada"] else "No")]) +
         '<h2>Evento asociado</h2>' + pre(login["registro"])),
        ("05_git", "Credencial ficticia en Git", "La herramienta detecta la exposición.", "20",
         tabla([("Herramienta ejecutada", "Gitleaks " + d["git"]["version"]),
                ("Credencial en el archivo actual", "Ausente" if d["git"]["secreto_ausente_del_archivo_actual"] else "Presente"),
                ("Hallazgos en el historial", d["git"]["hallazgos"]),
                ("Código de salida", f'{d["git"]["codigo_salida"]} — detección de una exposición')]) +
         '<h2>Hallazgo original de la herramienta</h2>' + pre(hallazgo) +
         '<p class="aclaracion">REDACTED es la redacción aplicada por Gitleaks. La credencial es sintética y no autentica ante un servicio real.</p>'),
        ("06_secretos", "Secreto retirado del código", "La aplicación obtiene la credencial desde una fuente externa.", "09",
         tabla([("Fuente utilizada", secreto["fuente"]),
                ("Clave externa de sesión consumida", "Sí" if secreto["clave_de_sesion_utilizada"] else "No"),
                ("Clave externa de cifrado consumida", "Sí" if secreto["clave_de_cifrado_utilizada"] else "No"),
                ("Inicio sin configuración", "Rechazado" if secreto["inicio_sin_secretos_rechazado"] else "Permitido")]) +
         '<h2>Huella SHA-256 de la clave ficticia externa</h2>' + pre(secreto["huella_sha256_clave_externa_ficticia"]) +
         '<h2>Huella SHA-256 del valor consumido por la aplicación</h2>' + pre(secreto["huella_sha256_clave_consumida"]) +
         '<p class="aclaracion">Las huellas coinciden. Se usan datos efímeros de prueba; no se muestran claves de la configuración local.</p>'),
        ("07_https", "Consulta mediante HTTPS", "La comunicación utiliza TLS correctamente.", "10",
         tabla([("Transporte comprobado", "Conexión de red real a 127.0.0.1:8444"),
                ("Solicitud enviada dentro de TLS", "GET /login HTTP/1.1"),
                ("Respuesta recibida", d["tls"]["respuesta"]),
                ("Protocolo negociado", d["tls"]["protocolo"]),
                ("Suite negociada", d["tls"]["suite"]),
                ("Cadena de la CA local", "Validada" if d["tls"]["certificado_validado_con_ca_local"] else "Rechazada"),
                ("Identidad verificada", d["tls"]["nombre_o_ip_verificado"]),
                ("Nombre incorrecto", "Rechazado" if d["tls"]["hostname_incorrecto_rechazado"] else "Aceptado")]) +
         '<p class="aclaracion">La prueba mantiene la validación del certificado. Este visor de resultados no es la conexión HTTPS ensayada.</p>'),
        ("08_logging", "Inicio de sesión fallido", "Se genera un registro sin revelar la contraseña.", "07 y 13",
         '<h2>Registro JSON leído tras el intento fallido</h2>' + pre(login["registro"]) +
         tabla([("Contraseña de prueba en el archivo de log", "Sí" if login["password_en_log"] else "No"),
                ("Correo de la cuenta en el archivo de log", "Sí" if login["correo_en_log"] else "No"),
                ("Resultado registrado", login["registro"]["resultado"]),
                ("Referencia para correlación", login["registro"]["solicitud_id"])])),
        ("09_error", "Error interno", "No expone claves, tokens ni detalles sensibles al usuario.", "11",
         tabla([("Condición de la prueba", "Excepción controlada con un texto centinela ficticio"),
                ("Respuesta observada", f'HTTP {error["http"]}'),
                ("Mensaje mostrado al usuario", error["mensaje_observado"]),
                ("Texto sensible en la respuesta", "Sí" if error["secreto_en_respuesta"] else "No"),
                ("Texto sensible en el archivo de log", "Sí" if error["secreto_en_log"] else "No")]) +
         '<h2>Evento de error registrado</h2>' + pre(error["registro"])),
    ]
    salida = EVIDENCIAS / "visuales"
    salida.mkdir(exist_ok=True)
    estilo = """*{box-sizing:border-box}body{margin:0;background:#edf1f3;color:#142c3c;font:16px/1.5 Arial,sans-serif}main{max-width:760px;margin:0;background:#fff;padding:26px 28px;border:1px solid #d2dce2}header{display:flex;justify-content:space-between;gap:12px;border-bottom:2px solid #163b50;padding-bottom:12px;margin-bottom:18px}.marca{font-weight:700;letter-spacing:.5px}.estado{font-size:12px;color:#12674e;font-weight:bold}h1{font-size:23px;line-height:1.2;margin:0 0 12px}h2{font-size:14px;margin:15px 0 7px}p{margin:9px 0}.esperado{padding:11px 13px;background:#edf4f7}.meta{color:#526672;font-size:12px}.aclaracion{font-size:12px;color:#445966}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #dbe3e7;padding:9px 6px;overflow-wrap:anywhere}th{width:45%;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f7;padding:12px;font:14px/1.45 Consolas,monospace;margin:7px 0}footer{margin-top:19px;padding-top:12px;border-top:1px solid #d2dce2;font-size:11px;color:#526672;overflow-wrap:anywhere}a{color:#15516f}nav{display:flex;justify-content:space-between;margin-top:13px}ol{padding-left:20px}li{margin-bottom:11px}@media(max-width:700px){main{margin:0;padding:22px}h1{font-size:21px}th{width:43%}}"""
    sha = hashlib.sha256(datos_crudos).hexdigest()
    enlaces = []
    for i, (slug, titulo, esperado, prueba, contenido) in enumerate(casos, 1):
        pagina = f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><title>{escape(titulo)}</title><style>{estilo}</style></head><body><main>
<header><span class="marca">MASI · Verificación de seguridad</span><span class="estado">CASO APROBADO</span></header>
<p class="meta">Prueba obligatoria {i:02d} de 09 · Casos automatizados {escape(prueba)}</p>
<h1>{escape(titulo)}</h1><p class="esperado"><strong>Resultado esperado:</strong> {escape(esperado)}</p>
{contenido}
<footer>Fuente: <a href="../resultados_pruebas.json">resultados_pruebas.json</a> · Ejecución UTC: {escape(resultados["fecha_utc"])}<br>
Captura del resultado registrado por las pruebas. Datos y cuentas ficticios.<br>SHA-256 del archivo fuente: {sha}
<nav><a href="index.html">Índice de evidencias</a><a href="{casos[i][0]+'.html' if i < len(casos) else 'index.html'}">{'Siguiente prueba' if i < len(casos) else 'Volver al índice'}</a></nav></footer>
</main></body></html>'''
        assert '<script>' not in pagina
        (salida / f"{slug}.html").write_text(pagina, encoding="utf-8")
        enlaces.append(f'<li><a href="{slug}.html">{i:02d}. {escape(titulo)}</a></li>')
    indice = f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Evidencias de las pruebas obligatorias</title><style>{estilo}</style></head><body><main>
<header><span class="marca">MASI · Laboratorio universitario</span></header><h1>Evidencias de las nueve pruebas obligatorias</h1>
<p>Este visor presenta los resultados de una ejecución real de pruebas.py. Las pantallas del portal y los archivos originales permiten contrastar cada resultado. Una captura facilita la revisión, pero no sustituye las pruebas ni sus fuentes.</p>
<p class="esperado">{resultados['total']} pruebas ejecutadas · {resultados['fallos']} fallos · {resultados['errores']} errores · {resultados['omitidas']} omisiones</p>
<ol>{''.join(enlaces)}</ol><footer>Ejecución UTC: {escape(resultados['fecha_utc'])} · Datos ficticios.<br>Fuente: <a href="../resultados_pruebas.json">resultados_pruebas.json</a></footer></main></body></html>'''
    (salida / "index.html").write_text(indice, encoding="utf-8")
    assert len(casos) == 9
    print("Visor de evidencias preparado: evidencias/visuales/index.html")


if __name__ == "__main__":
    generar()
