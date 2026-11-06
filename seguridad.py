"""Validación y criptografía del portal de laboratorio."""

import base64
import json
import re
import secrets
import unicodedata
from decimal import Decimal, InvalidOperation

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1,
                     hash_len=32, salt_len=16)


def verificar_password(hash_guardado, password):
    try:
        return KDF.verify(hash_guardado, password)
    except (InvalidHashError, VerificationError):
        return False


def validar_nombre(valor):
    nombre = " ".join(unicodedata.normalize("NFC", valor).split())
    if not 2 <= len(nombre) <= 60:
        raise ValueError("El nombre y el apellido deben tener entre 2 y 60 caracteres.")
    if not all(c.isalpha() or c in " '-" for c in nombre):
        raise ValueError("Use letras, espacios, apóstrofos o guiones en los nombres.")
    if not nombre[0].isalpha() or not nombre[-1].isalpha():
        raise ValueError("El nombre debe comenzar y terminar con una letra.")
    return nombre


def validar_correo(valor):
    correo = valor.strip().lower()
    if len(correo) > 254 or not re.fullmatch(
        r"[a-z0-9][a-z0-9._+\-]{0,63}@[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+", correo
    ):
        raise ValueError("Ingrese un correo válido, por ejemplo usuario@example.invalid.")
    if ".." in correo or correo.split("@")[0].endswith("."):
        raise ValueError("El correo tiene un formato inválido.")
    return correo


def validar_carnet(valor):
    carnet = valor.strip().upper()
    if not re.fullmatch(r"MASI-[0-9]{4}", carnet):
        raise ValueError("El identificador debe usar el formato MASI-0001.")
    return carnet


def validar_password(valor):
    if not 12 <= len(valor) <= 128:
        raise ValueError("La contraseña debe tener entre 12 y 128 caracteres.")
    return valor


def validar_busqueda(valor):
    texto = unicodedata.normalize("NFC", valor).strip()
    if len(texto) > 80 or any(unicodedata.category(c).startswith("C") for c in texto):
        raise ValueError("La búsqueda admite hasta 80 caracteres sin caracteres de control.")
    return texto


def validar_nota(valor):
    try:
        nota = Decimal(valor)
    except InvalidOperation as exc:
        raise ValueError("La calificación debe ser un número entre 0 y 100.") from exc
    if not nota.is_finite() or not 0 <= nota <= 100 or nota.as_tuple().exponent < -2:
        raise ValueError("La calificación admite de 0 a 100 y hasta dos decimales.")
    return str(nota.quantize(Decimal("0.01")))


def cifrar_expediente(clave, estudiante_id, datos):
    nonce = secrets.token_bytes(12)
    mensaje = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    aad = f"expediente:{estudiante_id}".encode("ascii")
    cifrado = AESGCM(clave).encrypt(nonce, mensaje, aad)
    return base64.b64encode(nonce + cifrado).decode("ascii")


def descifrar_expediente(clave, estudiante_id, valor):
    paquete = base64.b64decode(valor, validate=True)
    aad = f"expediente:{estudiante_id}".encode("ascii")
    mensaje = AESGCM(clave).decrypt(paquete[:12], paquete[12:], aad)
    return json.loads(mensaje)
