"""Repite las comprobaciones de la revisión con un portal temporal en Windows."""

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import shutil
import tempfile
import time
from unittest.mock import patch
from urllib.parse import urlencode
import zipfile



def verificar(work, repo, revision, salida):
    sys.path.insert(0, str(repo))
    from flask import render_template_string
    from cryptography.exceptions import InvalidTag
    from app import crear_app
    from pruebas import ControlesDelPortal, AnalizadorHTML, PASSWORD
    from seguridad import cifrar_expediente, descifrar_expediente

    evidence = {'revision': revision, 'fecha': datetime.now(timezone(timedelta(hours=-6))).strftime('%d/%m/%Y %H:%M:%S UTC−6')}

    def record(key, *values):
        evidence[key] = '\n'.join(str(x) for x in values)
        print(key, flush=True)

    def run(*args, timeout=22):
        return subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    c = ControlesDelPortal()
    c.setUp()
    try:
        bad = c.post('/registro', {'nombre':'Ana', 'apellido':'López', 'carnet':'../001', 'correo':'no-es-correo', 'password':PASSWORD}, '/registro')
        assert bad.status_code == 400
        c.login()
        invalid = c.post('/expediente/1', {'nota':'101','observacion':'Dato de laboratorio'}, '/expediente/1')
        assert invalid.status_code == 400 and '85.00' in c.get('/expediente/1').get_data(as_text=True)
        record('validacion', 'POST /registro | correo=no-es-correo | carnet=../001',
               f'HTTP {bad.status_code} | registro rechazado',
               f'POST /expediente/1 | nota=101 → HTTP {invalid.status_code}',
               'GET /expediente/1 → 85.00 | nota previa conservada')

        payload = "' OR 1=1 --"
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE estudiantes(nombre TEXT)')
            db.executemany('INSERT INTO estudiantes VALUES (?)', [('Ana',), ('Luis',)])
            vulnerable = db.execute(f"SELECT nombre FROM estudiantes WHERE nombre = '{payload}'").fetchall()
            segura = db.execute('SELECT nombre FROM estudiantes WHERE nombre = ?', (payload,)).fetchall()
        response = c.get('/estudiantes?' + urlencode({'q':payload}))
        assert len(vulnerable)==2 and not segura and response.status_code==200 and 'No se encontraron estudiantes' in response.get_data(as_text=True)
        assert 'MASI-0001' in c.get('/estudiantes?q=Ana').get_data(as_text=True)
        record('sql', f'Entrada repetida: {payload}', f'SQL concatenado: {vulnerable}', f'SQL parametrizado: {segura}',
               'GET /estudiantes con la misma entrada → HTTP 200',
               'Respuesta HTML: No se encontraron estudiantes',
               'GET /estudiantes?q=Ana → HTTP 200 | MASI-0001 presente')

        payload = "<script>document.documentElement.dataset.demo='ejecutado'</script>"
        with c.app.app_context():
            raw = render_template_string('<!doctype html><html><body>{{ texto|safe }}</body></html>', texto=payload)
        assert c.post('/comentarios', {'comentario':payload}, '/comentarios').status_code==302
        corrected = c.get('/comentarios').get_data(as_text=True)
        for doc, count in ((raw,1),(corrected,0)):
            parser=AnalizadorHTML()
            parser.feed(doc)
            assert parser.scripts==count
        escaped = re.search(r'<p class="texto-comentario">([^<]+)</p>',corrected).group(1)
        record('xss', 'Plantilla vulnerable | etiquetas script activas en el HTML: 1',
               'Respuesta real de GET /comentarios | etiquetas script activas: 0',
               'Fragmento de salida:', escaped)
        edge=Path('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')
        if not edge.is_file():
            record('xss_browser_pendiente', 'No se encontró Microsoft Edge en la ruta habitual.')
        else:
            try:
                results=[]
                for label, html in (('inseguro',raw),('corregido',corrected)):
                    f=work/(label+'.html')
                    f.write_text(html, encoding='utf-8')
                    b=run(str(edge),'--headless','--no-first-run','--disable-background-networking',
                          '--disable-extensions','--disable-gpu','--user-data-dir='+str(work/'perfil_prueba'),
                          '--dump-dom',f.as_uri(),timeout=9)
                    assert b.returncode==0 and '<html' in b.stdout
                    results.append('data-demo="ejecutado"' in b.stdout)
                assert results == [True,False]
                record('xss_browser','Motor Edge en modo sin interfaz, sobre los HTML de prueba',
                       'Plantilla vulnerable → data-demo="ejecutado"',
                       'Respuesta corregida → atributo data-demo ausente')
            except (AssertionError, OSError, subprocess.TimeoutExpired) as exc:
                record('xss_browser_pendiente', type(exc).__name__)

        payload='zip & echo MARCADOR_DE_PRUEBA'
        baseline=run(os.environ.get('COMSPEC','cmd.exe'),'/d','/c','echo Generando reporte '+payload)
        denied=c.post('/reportes/descargar',{'formato':payload},'/reportes')
        allowed=c.post('/reportes/descargar',{'formato':'zip'},'/reportes')
        assert baseline.returncode==0 and 'MARCADOR_DE_PRUEBA' in baseline.stdout.splitlines()
        assert denied.status_code==400 and allowed.status_code==200
        with zipfile.ZipFile(io.BytesIO(allowed.data)) as z:
            assert z.namelist()==['estudiantes.csv']
        record('comandos', 'Entrada: '+payload, 'Salida de la concatenación insegura:',
               baseline.stdout.strip(), f'Portal con la misma entrada → HTTP {denied.status_code}',
               f'Formato zip → HTTP {allowed.status_code} | ZIP: estudiantes.csv')

        hashes=c.filas("SELECT id, password_hash FROM usuarios WHERE id IN (2,3) ORDER BY id")
        assert len(hashes)==2 and all(s.startswith('$argon2id$') for _,s in hashes)
        assert hashes[0][1].split('$')[4]!=hashes[1][1].split('$')[4]
        c.login('ana@example.invalid')
        c.post('/logout',{},'/')
        wrong=c.post('/login',{'correo':'ana@example.invalid','password':'valor-ficticio-incorrecto'})
        assert wrong.status_code==401
        record('argon', 'SQLite: SELECT id, password_hash FROM usuarios WHERE id IN (2,3)',
               *(f'ID {i}: {h.split("$")[1]} | {h.split("$")[3]} | sal={h.split("$")[4]}' for i,h in hashes),
               'Hashes distintos para las dos cuentas con la misma clave de prueba.',
               'POST /login | clave correcta → HTTP 302',
               'POST /login | clave incorrecta → HTTP 401')

        c.login()
        dbpath=c.app.config['DATABASE']
        with closing(sqlite3.connect(dbpath)) as db:
            rows=db.execute('SELECT id, expediente FROM estudiantes ORDER BY id').fetchall()
            old_key=c.app.clave_datos
            assert 'Expediente académico ficticio' not in rows[0][1]
            before=descifrar_expediente(old_key,rows[0][0],rows[0][1])
            new_key=os.urandom(32)
            with db:
                for ident, ciphertext in rows:
                    data=descifrar_expediente(old_key,ident,ciphertext)
                    fresh=cifrar_expediente(new_key,ident,data)
                    assert descifrar_expediente(new_key,ident,fresh)==data
                    db.execute('UPDATE estudiantes SET expediente=? WHERE id=?',(fresh,ident))
            encrypted=db.execute('SELECT expediente FROM estudiantes WHERE id=1').fetchone()[0]
            assert encrypted!=rows[0][1]
            try:
                descifrar_expediente(old_key,1,encrypted)
            except InvalidTag:
                pass
            else:
                raise AssertionError('La clave anterior no debe descifrar el registro nuevo.')
        c.app.clave_datos=new_key
        own=c.get('/expediente/1')
        assert own.status_code==200 and before['nota'] in own.get_data(as_text=True)
        record('reposo', 'SQLite: SELECT expediente FROM estudiantes WHERE id=1',
               f'Prefijo almacenado: {rows[0][1][:42]}…',
               f'Rotación en base desechable: {len(rows)} expedientes recifrados',
               f'Prefijo tras rotación: {encrypted[:42]}…',
               'Descifrado con clave anterior → InvalidTag',
               f'GET /expediente/1 con clave nueva → HTTP {own.status_code} | nota {before["nota"]}')

        c.get('/administracion')
        updated=c.post('/expediente/1',{'nota':'94.50','observacion':'Modificación ficticia'},'/expediente/1')
        assert updated.status_code==302 and '94.50' in c.get('/expediente/1').get_data(as_text=True)
        for event in ('login_fallido','expediente_consultado','expediente_modificado','acceso_administrativo'):
            row=next(r for r in reversed(c.logs()) if r['evento']==event)
            record(event, json.dumps(row,ensure_ascii=False,indent=2))
        centinela='VALOR_INTERNO_FICTICIO'
        with patch('app.descifrar_expediente',side_effect=RuntimeError(centinela)):
            error=c.get('/expediente/1')
        html=error.get_data(as_text=True)
        event=next(r for r in reversed(c.logs()) if r['evento']=='error_interno')
        assert error.status_code==500 and event['solicitud_id'] in html
        assert centinela not in html and centinela not in Path(c.app.config['AUDIT_LOG']).read_text(encoding='utf-8')
        record('error','GET /expediente/1 con excepción inyectada durante la prueba',
               f'HTTP {error.status_code} | '+re.search('<h1>(.*?)</h1>',html).group(1),
               'Referencia en el HTML: '+event['solicitud_id'],
               'Evento JSON del servidor:',json.dumps(event,ensure_ascii=False,indent=2))
    finally:
        c.tearDown()

    etapa = 'Comprobar puerto local 8443'
    try:
        with socket.socket() as prueba_puerto:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                prueba_puerto.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            prueba_puerto.bind(('127.0.0.1', 8443))
        etapa = 'Preparar la copia temporal del portal'
        setup=run(sys.executable,'preparar.py')
        assert setup.returncode==0, setup.stderr[-500:]
        with patch.dict(os.environ,{},clear=True):
            try:
                crear_app()
            except RuntimeError as exc:
                record('secretos','crear_app() sin variables externas:',f'{type(exc).__name__}: {exc}',
                       'python preparar.py → '+setup.stdout.strip())
            else:
                raise AssertionError('El arranque sin secretos debe fallar.')
        etapa = 'Esperar el arranque de ejecutar.py en el puerto 8443'
        server=subprocess.Popen([sys.executable,'-u','ejecutar.py'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                text=True,encoding='utf-8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            for _ in range(30):
                if server.poll() is not None:
                    raise RuntimeError(server.stdout.read()[-500:])
                try:
                    with socket.create_connection(('127.0.0.1',8443),timeout=0.25):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError('El servidor no llegó a escuchar en 8443.')
            outputs=['python ejecutar.py','GET https://127.0.0.1:8443/login']
            for version in (ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3):
                etapa = f'Consultar /login con {version.name}'
                ctx=ssl.create_default_context(cafile=str(repo/'datos_locales/ca.crt'))
                ctx.minimum_version=ctx.maximum_version=version
                conn=http.client.HTTPSConnection('127.0.0.1',8443,context=ctx,timeout=5)
                try:
                    conn.connect()
                    protocol=conn.sock.version()
                    cipher=conn.sock.cipher()[0]
                    conn.request('GET','/login')
                    resp=conn.getresponse()
                    assert resp.status==200
                    resp.read()
                    outputs.append(f'{protocol} | {cipher} | HTTP {resp.status}')
                finally:
                    conn.close()
            etapa = 'Comprobar rechazo de identidad incorrecta'
            try:
                with socket.create_connection(('127.0.0.1',8443),timeout=5) as raw:
                    with ctx.wrap_socket(raw,server_hostname='nombre-ajeno.invalid'):
                        raise AssertionError('Nombre incorrecto aceptado')
            except ssl.SSLCertVerificationError:
                outputs.append('Nombre incorrecto → SSLCertVerificationError')
            outputs.append('CA local e identidad 127.0.0.1 verificadas.')
            record('tls8443',*outputs)
        finally:
            server.terminate()
            server.communicate(timeout=6)
    except (OSError, AssertionError, RuntimeError, subprocess.SubprocessError) as exc:
        mensaje=str(exc).replace(str(work),'[TEMPORAL]')
        record('tls_pendiente', etapa, type(exc).__name__+': '+mensaje[:320])

    suite=run(sys.executable,'pruebas.py',timeout=35)
    record('suite',suite.stdout.strip())
    result=json.loads((repo/'evidencias/resultados_pruebas.json').read_text(encoding='utf-8'))
    record('estado_suite',json.dumps({k:result[k] for k in ('total','fallos','errores','omitidas')},ensure_ascii=False))
    if result['detalles'].get('git'):
        report=json.loads((repo/'evidencias/gitleaks_historial.json').read_text(encoding='utf-8'))
        hit=report[0]
        assert hit['Secret']=='REDACTED'
        record('git',(repo/'evidencias/git_historial.txt').read_text(encoding='utf-8').strip(),
               (repo/'evidencias/gitleaks_salida.txt').read_text(encoding='utf-8').strip(),
               json.dumps({k:hit[k] for k in ('RuleID','File','Commit','StartLine','Secret')},ensure_ascii=False,indent=2))
    with salida.open('x', encoding='utf-8') as archivo:
        json.dump(evidence, archivo, ensure_ascii=False, indent=2)
    print(f'Resultados guardados en {salida}', flush=True)
    return int(suite.returncode != 0 or result['omitidas'] != 0 or
               'tls8443' not in evidence or 'xss_browser' not in evidence or 'git' not in evidence)


def main():
    parser = argparse.ArgumentParser(description="Verificación local del portal con datos ficticios")
    parser.add_argument("--salida", default="resultados_revision_local.json",
                        help="Ruta nueva del informe JSON")
    args = parser.parse_args()
    salida = Path(args.salida).resolve()
    if salida.exists():
        parser.error("La ruta de salida ya existe. Seleccione un nombre nuevo.")
    if not salida.parent.is_dir():
        parser.error("La carpeta de salida debe existir.")

    raiz = Path(__file__).resolve().parent.parent
    nombre = os.environ.get("GITLEAKS_BIN", str(raiz / ".herramientas/gitleaks.exe"))
    gitleaks = shutil.which(nombre) or (str(Path(nombre).resolve()) if Path(nombre).is_file() else None)
    if not gitleaks:
        parser.error("Instale Gitleaks con instalar_gitleaks.ps1 o defina GITLEAKS_BIN.")
    os.environ["GITLEAKS_BIN"] = gitleaks
    os.environ["PYTHONUTF8"] = "1"
    revision = "Copia sin metadatos Git"
    if (raiz / ".git").exists():
        git = subprocess.run(["git", "-C", str(raiz), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True)
        revision = git.stdout.strip()
    anterior = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="revision_portal_") as directorio:
        temporal = Path(directorio)
        copia = temporal / "portal"
        copia.mkdir()
        for nombre in ("app.py", "ejecutar.py", "preparar.py", "pruebas.py",
                       "seguridad.py", ".gitleaks.toml"):
            shutil.copy2(raiz / nombre, copia / nombre)
        for nombre in ("templates", "static"):
            shutil.copytree(raiz / nombre, copia / nombre)
        try:
            os.chdir(copia)
            return verificar(temporal, copia, revision, salida)
        finally:
            os.chdir(anterior)


if __name__ == "__main__":
    raise SystemExit(main())
