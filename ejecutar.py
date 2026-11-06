"""Servidor HTTPS de uso exclusivo en el equipo local."""

import ssl
from werkzeug.serving import make_server, WSGIRequestHandler

from app import crear_app
from preparar import DATOS, cargar_configuracion


class SolicitudSinDatosSensibles(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        # Los eventos se registran en JSON sin copiar URL, cabeceras ni formularios.
        pass


def main():
    cargar_configuracion()
    app = crear_app()
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.load_cert_chain(DATOS / "servidor.crt", DATOS / "servidor.key")
    servidor = make_server("127.0.0.1", 8443, app, threaded=True,
                          ssl_context=contexto, request_handler=SolicitudSinDatosSensibles)
    print("Portal local: https://127.0.0.1:8443", flush=True)
    print("Accesos: datos_locales/accesos.txt. Para detener: Ctrl+C.", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()
        app.registro.close()


if __name__ == "__main__":
    main()
