import struct
from dataclasses import dataclass

from cryptostore.errors import VerificationError
from cryptostore.primitives.public_key import PUBLIC_KEY_SIZE, SealedSecret, hpke_open, hpke_seal
from cryptostore.primitives.symmetric import SYMMETRIC_KEY_SIZE
from cryptostore.protocol.file_blocks import FILE_ID_SIZE
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.public_identity import PublicIdentity
from cryptostore.protocol.serialization import from_base64, from_hex, require_field, to_base64

_GRANT_CONTEXT_LABEL = b"p5/grant/v1"


# Envolvente: la clave de datos del archivo sellada para un destinatario (~80 B, sin importar el tamaño del archivo)
@dataclass(frozen=True)
class AccessGrant:
    file_id: bytes
    content_version: int
    recipient_id: str
    sealed_data_key: SealedSecret

    @classmethod
    def issue(cls, *, data_encryption_key: bytes, manifest: SignedManifest, recipient: PublicIdentity) -> "AccessGrant":
        body = manifest.body
        # Compartir = sellar la clave de datos con la clave pública del destinatario.
        # Los bloques cifrados no se tocan ni se vuelven a cifrar
        sealed = hpke_seal(
            recipient.encryption_public_key,
            _grant_context(body.file_id, body.content_version, recipient.user_id),
            # Atada al manifiesto exacto: no sirve para otro archivo ni otra versión
            manifest.digest,
            data_encryption_key,
        )
        return cls(body.file_id, body.content_version, recipient.user_id, sealed)

    def open(self, *, manifest: SignedManifest, recipient_id: str, recipient_encryption_private_key: bytes) -> bytes:
        body = manifest.body
        if (self.file_id, self.content_version, self.recipient_id) != (body.file_id, body.content_version, recipient_id):
            raise VerificationError("la envolvente no corresponde a este archivo, versión o destinatario")
        # Solo la clave privada del destinatario, con el mismo contexto y manifiesto, abre el sello
        data_encryption_key = hpke_open(
            recipient_encryption_private_key,
            _grant_context(self.file_id, self.content_version, recipient_id),
            manifest.digest,
            self.sealed_data_key,
        )
        if len(data_encryption_key) != SYMMETRIC_KEY_SIZE:
            raise VerificationError("la clave de datos recuperada no tiene 32 bytes")
        return data_encryption_key

    def to_json_dict(self) -> dict:
        return {
            "file_id": self.file_id.hex(),
            "content_version": self.content_version,
            "recipient_id": self.recipient_id,
            "encapsulated_key": to_base64(self.sealed_data_key.encapsulated_key),
            "sealed_data_key": to_base64(self.sealed_data_key.ciphertext),
        }

    @classmethod
    def from_json_dict(cls, data: dict) -> "AccessGrant":
        return cls(
            file_id=from_hex(require_field(data, "file_id", str), FILE_ID_SIZE),
            content_version=require_field(data, "content_version", int),
            recipient_id=require_field(data, "recipient_id", str),
            sealed_data_key=SealedSecret(
                encapsulated_key=from_base64(require_field(data, "encapsulated_key", str), PUBLIC_KEY_SIZE),
                ciphertext=from_base64(require_field(data, "sealed_data_key", str)),
            ),
        )


def _grant_context(file_id: bytes, content_version: int, recipient_id: str) -> bytes:
    return _GRANT_CONTEXT_LABEL + file_id + struct.pack(">I", content_version) + recipient_id.encode("ascii")
