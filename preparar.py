"""Genera secretos y certificados locales sin sobrescribir un laboratorio previo."""

import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from app import crear_app, inicializar_base

RAIZ = Path(__file__).resolve().parent
DATOS = RAIZ / "datos_locales"


def guardar_privado(ruta, contenido):
    descriptor = os.open(str(ruta), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(contenido)


def preparar_certificados(destino):
    ahora = datetime.now(timezone.utc)
    clave_ca = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nombre_ca = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autoridad local del laboratorio MASI")])
    ca = (x509.CertificateBuilder().subject_name(nombre_ca).issuer_name(nombre_ca)
          .public_key(clave_ca.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(ahora - timedelta(minutes=5)).not_valid_after(ahora + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(clave_ca, hashes.SHA256()))
    clave_servidor = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    servidor = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(nombre_ca).public_key(clave_servidor.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(ahora - timedelta(minutes=5)).not_valid_after(ahora + timedelta(days=7))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(clave_ca, hashes.SHA256()))
    guardar_privado(destino / "servidor.key", clave_servidor.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    guardar_privado(destino / "servidor.crt", servidor.public_bytes(serialization.Encoding.PEM))
    guardar_privado(destino / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    # La clave de la CA no se conserva después de emitir el certificado local.


def cargar_configuracion():
    configuracion = json.loads((DATOS / "config.json").read_text(encoding="utf-8"))
    for nombre in ("PORTAL_SESSION_SECRET", "PORTAL_DATA_KEY"):
        os.environ[nombre] = configuracion[nombre]


def main():
    DATOS.mkdir(mode=0o700, exist_ok=True)
    if (DATOS / "config.json").exists():
        requeridos = ["portal.sqlite3", "servidor.crt", "servidor.key", "ca.crt", "accesos.txt"]
        if not all((DATOS / nombre).is_file() for nombre in requeridos):
            raise RuntimeError("La preparación anterior está incompleta. Revise datos_locales sin borrar sus claves.")
        print("El laboratorio ya está preparado. Se conservaron sus claves y sus datos.")
        return
    if any(DATOS.iterdir()):
        raise RuntimeError("Hay una preparación parcial. Conserve esos archivos y revise el estado antes de continuar.")
    configuracion = {
        "PORTAL_SESSION_SECRET": secrets.token_urlsafe(48),
        "PORTAL_DATA_KEY": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    guardar_privado(DATOS / "config.json", json.dumps(configuracion).encode("utf-8"))
    cargar_configuracion()
    preparar_certificados(DATOS)
    password = "Demo-" + secrets.token_urlsafe(15)
    app = crear_app()
    try:
        inicializar_base(app, password)
    finally:
        app.registro.close()
    acceso = ("ACCESOS FICTICIOS DEL LABORATORIO\n\nAdministrador: admin@example.invalid\n"
              "Estudiante 1: ana@example.invalid\nEstudiante 2: luis@example.invalid\n"
              f"Contraseña inicial de las tres cuentas: {password}\n\n"
              "Este archivo es local y no debe incluirse en el repositorio ni en la entrega.\n")
    guardar_privado(DATOS / "accesos.txt", acceso.encode("utf-8"))
    print("Laboratorio preparado. Consulte datos_locales/accesos.txt para iniciar sesión.")


if __name__ == "__main__":
    main()
