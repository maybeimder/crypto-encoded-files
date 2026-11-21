import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptostore.errors import VerificationError

SYMMETRIC_KEY_SIZE = 32
AEAD_NONCE_SIZE = 12  # número que nunca debe repetirse con la misma clave
AEAD_TAG_SIZE = 16    # etiqueta que delata cualquier alteración del cifrado
SHA256_DIGEST_SIZE = 32


def random_bytes(length: int) -> bytes:
    # Generador seguro del sistema operativo
    return os.urandom(length)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_subkey(master_key: bytes, purpose_label: bytes, length: int = SYMMETRIC_KEY_SIZE) -> bytes:
    # HKDF (RFC 5869): cada etiqueta produce una clave independiente de las demás
    key_derivation = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=purpose_label)
    return key_derivation.derive(master_key)


# Cifrado autenticado ChaCha20-Poly1305 (RFC 8439)
class AuthenticatedCipher:
    def __init__(self, key: bytes):
        if len(key) != SYMMETRIC_KEY_SIZE:
            raise ValueError(f"la clave debe tener {SYMMETRIC_KEY_SIZE} bytes")
        self._cipher = ChaCha20Poly1305(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
        # Devuelve cifrado + etiqueta. associated_data no se cifra pero queda atado:
        # al descifrar hay que presentar exactamente los mismos bytes
        return self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes) -> bytes:
        try:
            return self._cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag as error:
            # Etiqueta inválida: datos alterados, fuera de lugar o clave incorrecta
            raise VerificationError(
                "el cifrado autenticado no verificó: datos alterados, fuera de lugar o clave incorrecta"
            ) from error
