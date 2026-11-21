from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.exceptions import PyHPKEError

from cryptostore.errors import VerificationError

PUBLIC_KEY_SIZE = 32
PRIVATE_KEY_SIZE = 32
SIGNATURE_SIZE = 64

_RAW_PUBLIC_KEY_FORMAT = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
# HPKE (RFC 9180) modo base: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
_HPKE_SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
)


@dataclass(frozen=True)
class KeyPair:
    private_key: bytes
    public_key: bytes


# X25519: par para recibir secretos (la pública sella, solo la privada abre)
def generate_encryption_keypair() -> KeyPair:
    private_key = X25519PrivateKey.generate()
    return KeyPair(private_key.private_bytes_raw(), private_key.public_key().public_bytes(**_RAW_PUBLIC_KEY_FORMAT))


# Ed25519: par para firmar (la privada firma, cualquiera verifica con la pública)
def generate_signing_keypair() -> KeyPair:
    private_key = Ed25519PrivateKey.generate()
    return KeyPair(private_key.private_bytes_raw(), private_key.public_key().public_bytes(**_RAW_PUBLIC_KEY_FORMAT))


def encryption_public_key_from_private(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(**_RAW_PUBLIC_KEY_FORMAT)


def signing_public_key_from_private(private_key: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(**_RAW_PUBLIC_KEY_FORMAT)


def sign(signing_private_key: bytes, domain_label: bytes, message: bytes) -> bytes:
    # La etiqueta de dominio impide presentar una firma de un propósito como válida para otro
    return Ed25519PrivateKey.from_private_bytes(signing_private_key).sign(domain_label + message)


def verify_signature(signing_public_key: bytes, domain_label: bytes, message: bytes, signature: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(signing_public_key).verify(signature, domain_label + message)
    except (InvalidSignature, ValueError) as error:
        raise VerificationError("la firma no es válida para esta clave pública") from error


@dataclass(frozen=True)
class SealedSecret:
    encapsulated_key: bytes  # clave pública efímera, de un solo uso (32 B)
    ciphertext: bytes        # secreto cifrado + etiqueta (16 B)


def hpke_seal(recipient_public_key: bytes, context_info: bytes, associated_data: bytes, secret: bytes) -> SealedSecret:
    recipient_key = _HPKE_SUITE.kem.deserialize_public_key(recipient_public_key)
    # Crea un par efímero y hace Diffie-Hellman con la clave del destinatario:
    # el secreto compartido solo lo puede recalcular quien tenga la clave privada
    encapsulated_key, sender_context = _HPKE_SUITE.create_sender_context(recipient_key, info=context_info)
    # Cifra con una clave derivada de ese secreto compartido y de context_info
    ciphertext = sender_context.seal(secret, aad=associated_data)
    # La clave efímera pública viaja junto al cifrado para que el destinatario repita el cálculo
    return SealedSecret(encapsulated_key, ciphertext)


def hpke_open(recipient_private_key: bytes, context_info: bytes, associated_data: bytes, sealed: SealedSecret) -> bytes:
    try:
        private_key = _HPKE_SUITE.kem.deserialize_private_key(recipient_private_key)
        # Mismo Diffie-Hellman desde el otro lado: clave privada propia + clave efímera recibida
        recipient_context = _HPKE_SUITE.create_recipient_context(
            sealed.encapsulated_key, private_key, info=context_info
        )
        return recipient_context.open(sealed.ciphertext, aad=associated_data)
    except (PyHPKEError, ValueError) as error:
        # Clave privada, contexto o datos asociados distintos a los del sellado
        raise VerificationError("no se pudo abrir la envolvente HPKE") from error
