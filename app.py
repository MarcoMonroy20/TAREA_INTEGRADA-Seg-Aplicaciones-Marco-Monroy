"""Portal universitario para pruebas locales con datos ficticios."""

import base64
from contextlib import closing
import csv
import io
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.exceptions import HTTPException, SecurityError

from seguridad import (KDF, cifrar_expediente, descifrar_expediente,
                       validar_busqueda, validar_carnet, validar_correo,
                       validar_nombre, validar_nota, validar_password,
                       verificar_password)


class RegistroObligatorio(RotatingFileHandler):
    def handleError(self, record):
        raise OSError("No fue posible escribir el registro de seguridad.")


def conexion():
    if "db" not in g:
        g.db = sqlite3.connect(g.app.config["DATABASE"], timeout=5)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def registrar_evento(evento, resultado="correcto", objeto_id=None):
    registro = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "evento": evento,
        "actor_id": g.user["id"] if getattr(g, "user", None) else None,
        "objeto_id": objeto_id,
        "resultado": resultado,
        "solicitud_id": getattr(g, "solicitud_id", str(uuid.uuid4())),
    }
    record = logging.LogRecord("seguridad", logging.INFO, "", 0,
                               json.dumps(registro, ensure_ascii=False), (), None)
    g.app.registro.handle(record)


def requerir_acceso(admin=False):
    def decorar(funcion):
        @wraps(funcion)
        def protegida(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            if admin and g.user["rol"] != "administrador":
                registrar_evento("acceso_denegado", "rechazado")
                abort(403)
            return funcion(*args, **kwargs)
        return protegida
    return decorar


def crear_app(configuracion=None):
    app = Flask(__name__)
    raiz = Path(__file__).resolve().parent
    app.config.update(
        SECRET_KEY=os.environ.get("PORTAL_SESSION_SECRET"),
        DATA_KEY=os.environ.get("PORTAL_DATA_KEY"),
        DATABASE=str(raiz / "datos_locales" / "portal.sqlite3"),
        AUDIT_LOG=str(raiz / "datos_locales" / "seguridad.jsonl"),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
        MAX_CONTENT_LENGTH=16384,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
    )
    if configuracion:
        app.config.update(configuracion)
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("Configure una clave de sesión externa de al menos 32 caracteres.")
    try:
        clave = base64.b64decode(app.config["DATA_KEY"], validate=True)
        if len(clave) != 32:
            raise ValueError("Longitud incorrecta")
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Configure una clave externa AES de 32 bytes en Base64.") from exc
    app.clave_datos = clave
    ruta_log = Path(app.config["AUDIT_LOG"])
    ruta_log.parent.mkdir(parents=True, exist_ok=True)
    app.registro = RegistroObligatorio(ruta_log, maxBytes=1048576,
                                       backupCount=3, encoding="utf-8")
    app.registro.setFormatter(logging.Formatter("%(message)s"))
    app.hash_sin_usuario = KDF.hash(secrets.token_urlsafe(24))

    @app.teardown_appcontext
    def cerrar_db(error=None):
        db = g.pop("db", None)
        if db:
            db.close()

    @app.before_request
    def controles():
        g.app = app
        g.solicitud_id = str(uuid.uuid4())
        g.user = None
        if not request.is_secure:
            abort(400)
        if session.get("uid"):
            g.user = conexion().execute("SELECT * FROM usuarios WHERE id = ?",
                                        (session["uid"],)).fetchone()
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not token.isascii() or not secrets.compare_digest(token, session["csrf"]):
                registrar_evento("csrf_rechazado", "rechazado")
                abort(400)

    @app.after_request
    def cabeceras(respuesta):
        respuesta.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Strict-Transport-Security": "max-age=86400",
        })
        return respuesta

    @app.errorhandler(Exception)
    def error_seguro(error):
        if isinstance(error, SecurityError):
            return "Solicitud no válida.", 400
        codigo = error.code if isinstance(error, HTTPException) else 500
        try:
            if codigo >= 500:
                registrar_evento("error_interno", "error")
        except OSError:
            codigo = 503
        mensajes = {
            400: "La solicitud no es válida. Use HTTPS y vuelva a abrir el formulario.",
            403: "No tiene permiso para consultar este recurso.",
            404: "No se encontró el recurso solicitado.",
            405: "El método solicitado no está permitido.",
            413: "La solicitud supera el tamaño permitido.",
            429: "Se alcanzó el límite de intentos. Espere un minuto.",
            500: "No fue posible completar la operación.",
            503: "El servicio no está disponible temporalmente.",
        }
        return render_template("error.html", codigo=codigo,
                               mensaje=mensajes.get(codigo, "No fue posible procesar la solicitud."),
                               referencia=getattr(g, "solicitud_id", "")), codigo

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            correo = request.form.get("correo", "").strip().lower()[:254]
            password = request.form.get("password", "")
            usuario = conexion().execute("SELECT * FROM usuarios WHERE correo = ?", (correo,)).fetchone()
            if usuario and usuario["bloqueado_hasta"] > time.time():
                registrar_evento("login_bloqueado", "rechazado", usuario["id"])
                abort(429)
            correcto = len(password) <= 128 and verificar_password(
                usuario["password_hash"] if usuario else app.hash_sin_usuario, password)
            if usuario and correcto:
                g.user = usuario
                nuevo_hash = KDF.hash(password) if KDF.check_needs_rehash(usuario["password_hash"]) else usuario["password_hash"]
                conexion().execute("UPDATE usuarios SET fallos = 0, bloqueado_hasta = 0, password_hash = ? WHERE id = ?", (nuevo_hash, usuario["id"]))
                registrar_evento("login_correcto")
                conexion().commit()
                session.clear()
                session["uid"] = usuario["id"]
                session["csrf"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("inicio"))
            if usuario:
                fallos = usuario["fallos"] + 1 if usuario["bloqueado_hasta"] == 0 else 1
                limite = time.time() + 60 if fallos >= 5 else 0
                conexion().execute("UPDATE usuarios SET fallos = ?, bloqueado_hasta = ? WHERE id = ?", (fallos, limite, usuario["id"]))
            registrar_evento("login_fallido", "rechazado", usuario["id"] if usuario else None)
            conexion().commit()
            flash("Credenciales incorrectas.", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/registro", methods=["GET", "POST"])
    def registro():
        if request.method == "POST":
            try:
                correo = validar_correo(request.form.get("correo", ""))
                nombre = validar_nombre(request.form.get("nombre", ""))
                apellido = validar_nombre(request.form.get("apellido", ""))
                carnet = validar_carnet(request.form.get("carnet", ""))
                password = validar_password(request.form.get("password", ""))
                db = conexion()
                with db:
                    cursor = db.execute("INSERT INTO estudiantes (carnet, nombre, apellido, expediente) VALUES (?, ?, ?, '')", (carnet, nombre, apellido))
                    ident = cursor.lastrowid
                    cifrado = cifrar_expediente(app.clave_datos, ident, {"nota": "0.00", "observacion": "Registro de laboratorio"})
                    db.execute("UPDATE estudiantes SET expediente = ? WHERE id = ?", (cifrado, ident))
                    db.execute("INSERT INTO usuarios (correo, password_hash, rol, estudiante_id) VALUES (?, ?, 'estudiante', ?)", (correo, KDF.hash(password), ident))
                    registrar_evento("registro_usuario", objeto_id=ident)
                flash("Registro completado. Ya puede iniciar sesión.", "correcto")
                return redirect(url_for("login"))
            except ValueError as error:
                registrar_evento("validacion_rechazada", "rechazado")
                flash(str(error), "error")
                return render_template("registro.html"), 400
            except sqlite3.IntegrityError:
                flash("No fue posible registrar esos datos. Revise el correo y el identificador.", "error")
                return render_template("registro.html"), 409
        return render_template("registro.html")

    @app.post("/logout")
    @requerir_acceso()
    def logout():
        registrar_evento("cierre_sesion")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @requerir_acceso()
    def inicio():
        return render_template("inicio.html")

    @app.get("/estudiantes")
    @requerir_acceso(admin=True)
    def estudiantes():
        try:
            termino = validar_busqueda(request.args.get("q", ""))
        except ValueError as error:
            flash(str(error), "error")
            return render_template("estudiantes.html", estudiantes=[], termino=""), 400
        patron = "%" + termino.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        filas = conexion().execute(
            "SELECT id, carnet, nombre, apellido FROM estudiantes WHERE nombre LIKE ? ESCAPE '\\' OR apellido LIKE ? ESCAPE '\\' OR carnet LIKE ? ESCAPE '\\' ORDER BY id LIMIT 100",
            (patron, patron, patron)).fetchall()
        registrar_evento("busqueda_estudiantes")
        return render_template("estudiantes.html", estudiantes=filas, termino=termino)

    @app.route("/expediente/<int:ident>", methods=["GET", "POST"])
    @requerir_acceso()
    def expediente(ident):
        if g.user["rol"] != "administrador" and g.user["estudiante_id"] != ident:
            registrar_evento("expediente_denegado", "rechazado", ident)
            abort(403)
        alumno = conexion().execute("SELECT * FROM estudiantes WHERE id = ?", (ident,)).fetchone()
        if not alumno:
            abort(404)
        datos = descifrar_expediente(app.clave_datos, ident, alumno["expediente"])
        if request.method == "POST":
            if g.user["rol"] != "administrador":
                abort(403)
            try:
                datos["nota"] = validar_nota(request.form.get("nota", ""))
                observacion = request.form.get("observacion", "").strip()
                if len(observacion) > 500 or any(ord(c) < 32 for c in observacion):
                    raise ValueError("La observación admite hasta 500 caracteres sin caracteres de control.")
                datos["observacion"] = observacion
            except ValueError as error:
                flash(str(error), "error")
                return render_template("expediente.html", alumno=alumno, datos=datos), 400
            with conexion():
                conexion().execute("UPDATE estudiantes SET expediente = ? WHERE id = ?", (cifrar_expediente(app.clave_datos, ident, datos), ident))
                registrar_evento("expediente_modificado", objeto_id=ident)
            flash("Expediente actualizado.", "correcto")
            return redirect(url_for("expediente", ident=ident))
        registrar_evento("expediente_consultado", objeto_id=ident)
        return render_template("expediente.html", alumno=alumno, datos=datos)

    @app.route("/comentarios", methods=["GET", "POST"])
    @requerir_acceso()
    def comentarios():
        if request.method == "POST":
            texto = request.form.get("comentario", "").strip()
            if not texto or len(texto) > 1000 or "\x00" in texto:
                abort(400)
            with conexion():
                conexion().execute("INSERT INTO comentarios (usuario_id, texto) VALUES (?, ?)", (g.user["id"], texto))
                registrar_evento("comentario_publicado")
            return redirect(url_for("comentarios"))
        filas = conexion().execute("SELECT id, usuario_id, texto FROM comentarios ORDER BY id DESC LIMIT 50").fetchall()
        return render_template("comentarios.html", comentarios=filas)

    @app.get("/reportes")
    @requerir_acceso(admin=True)
    def reportes():
        return render_template("reportes.html")

    @app.post("/reportes/descargar")
    @requerir_acceso(admin=True)
    def descargar_reporte():
        formato = request.form.get("formato", "")
        if formato not in {"csv", "zip"}:
            registrar_evento("reporte_rechazado", "rechazado")
            abort(400)
        contenido = io.StringIO(newline="")
        escritor = csv.writer(contenido)
        escritor.writerow(["Identificador", "Nombre", "Apellido", "Calificacion"])
        for alumno in conexion().execute("SELECT * FROM estudiantes ORDER BY id"):
            datos = descifrar_expediente(app.clave_datos, alumno["id"], alumno["expediente"])
            escritor.writerow([alumno["carnet"], alumno["nombre"], alumno["apellido"], datos["nota"]])
        datos_csv = contenido.getvalue().encode("utf-8-sig")
        registrar_evento("reporte_generado")
        if formato == "csv":
            return send_file(io.BytesIO(datos_csv), mimetype="text/csv", as_attachment=True, download_name="estudiantes.csv")
        comprimido = io.BytesIO()
        with zipfile.ZipFile(comprimido, "w", compression=zipfile.ZIP_DEFLATED) as archivo:
            archivo.writestr("estudiantes.csv", datos_csv)
        comprimido.seek(0)
        return send_file(comprimido, mimetype="application/zip", as_attachment=True, download_name="reporte.zip")

    @app.get("/administracion")
    @requerir_acceso(admin=True)
    def administracion():
        registrar_evento("acceso_administrativo")
        return render_template("administracion.html")

    return app


def inicializar_base(app, password_demo):
    ruta = Path(app.config["DATABASE"])
    if ruta.exists():
        raise FileExistsError("La base ya existe. No se sobrescribieron los datos.")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(ruta)) as db, db:
        db.executescript("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE estudiantes (
                id INTEGER PRIMARY KEY, carnet TEXT UNIQUE NOT NULL,
                nombre TEXT NOT NULL, apellido TEXT NOT NULL, expediente TEXT NOT NULL);
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY, correo TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, rol TEXT NOT NULL CHECK (rol IN ('estudiante', 'administrador')),
                estudiante_id INTEGER REFERENCES estudiantes(id),
                fallos INTEGER NOT NULL DEFAULT 0, bloqueado_hasta REAL NOT NULL DEFAULT 0);
            CREATE TABLE comentarios (
                id INTEGER PRIMARY KEY, usuario_id INTEGER NOT NULL REFERENCES usuarios(id), texto TEXT NOT NULL);
        """)
        db.execute("INSERT INTO usuarios (correo, password_hash, rol) VALUES (?, ?, 'administrador')", ("admin@example.invalid", KDF.hash(password_demo)))
        for carnet, nombre, apellido, nota, correo in [
            ("MASI-0001", "Ana", "López", "85.00", "ana@example.invalid"),
            ("MASI-0002", "Luis", "Pérez", "90.00", "luis@example.invalid"),
        ]:
            cur = db.execute("INSERT INTO estudiantes (carnet, nombre, apellido, expediente) VALUES (?, ?, ?, '')", (carnet, nombre, apellido))
            ident = cur.lastrowid
            cifrado = cifrar_expediente(app.clave_datos, ident, {"nota": nota, "observacion": "Expediente académico ficticio"})
            db.execute("UPDATE estudiantes SET expediente = ? WHERE id = ?", (cifrado, ident))
            db.execute("INSERT INTO usuarios (correo, password_hash, rol, estudiante_id) VALUES (?, ?, 'estudiante', ?)", (correo, KDF.hash(password_demo), ident))
