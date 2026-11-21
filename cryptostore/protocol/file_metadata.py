import json
import struct
from dataclasses import dataclass

from cryptostore.errors import FormatError, VerificationError
from cryptostore.primitives.symmetric import AEAD_NONCE_SIZE, AEAD_TAG_SIZE, AuthenticatedCipher, random_bytes
from cryptostore.protocol.file_blocks import MAXIMUM_FILE_SIZE, FileKeyMaterial
from cryptostore.protocol.serialization import canonical_json, require_field

_METADATA_ASSOCIATED_DATA_TAG = b"META\x01"


# Nombre, tipo y tamaño real: el servidor no debe verlos, viajan cifrados en el manifiesto
@dataclass(frozen=True)
class FileMetadata:
    name: str
    mime_type: str
    plaintext_size: int

    def encrypt(self, key_material: FileKeyMaterial) -> bytes:
        # Nonce aleatorio: seguro porque la subclave de metadatos cifra una sola vez por versión
        nonce = random_bytes(AEAD_NONCE_SIZE)
        content = canonical_json({"name": self.name, "mime_type": self.mime_type, "size": self.plaintext_size})
        cipher = AuthenticatedCipher(key_material.metadata_key)
        # Se guarda nonce | cifrado | etiqueta
        return nonce + cipher.encrypt(nonce, content, _associated_data_for(key_material))

    @classmethod
    def decrypt(cls, key_material: FileKeyMaterial, encrypted_metadata: bytes) -> "FileMetadata":
        if len(encrypted_metadata) < AEAD_NONCE_SIZE + AEAD_TAG_SIZE:
            raise VerificationError("metadatos cifrados demasiado cortos")
        nonce, ciphertext = encrypted_metadata[:AEAD_NONCE_SIZE], encrypted_metadata[AEAD_NONCE_SIZE:]
        cipher = AuthenticatedCipher(key_material.metadata_key)
        content = json.loads(cipher.decrypt(nonce, ciphertext, _associated_data_for(key_material)))
        plaintext_size = require_field(content, "size", int)
        if not 0 <= plaintext_size <= MAXIMUM_FILE_SIZE:
            raise FormatError("tamaño declarado fuera de rango")
        return cls(require_field(content, "name", str), require_field(content, "mime_type", str), plaintext_size)


def _associated_data_for(key_material: FileKeyMaterial) -> bytes:
    # Ata los metadatos a su archivo y versión: no se pueden trasplantar a otro manifiesto
    return _METADATA_ASSOCIATED_DATA_TAG + key_material.file_id + struct.pack(">I", key_material.content_version)
