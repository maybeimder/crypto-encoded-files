import json
import os
from dataclasses import dataclass

from cryptostore.atomic_files import write_file_atomically
from cryptostore.errors import FormatError, VerificationError
from cryptostore.primitives.symmetric import AEAD_NONCE_SIZE, AuthenticatedCipher, derive_subkey, random_bytes
from cryptostore.protocol.file_blocks import FILE_ID_SIZE, NONCE_PREFIX_SIZE, FileKeyMaterial
from cryptostore.protocol.serialization import canonical_json, from_base64, from_hex, require_field, to_base64

_CHECKPOINT_KEY_LABEL = b"p5/local-checkpoint/v1"
_CHECKPOINT_ASSOCIATED_DATA = b"CHECKPOINT\x01"


# Lo necesario para continuar una carga cortada con la misma clave, sin reutilizarla para otro contenido
@dataclass(frozen=True)
class UploadCheckpoint:
    source_path: str
    source_size: int
    source_modified_ns: int
    plaintext_block_digests: tuple[bytes, ...]
    block_size: int
    key_material: FileKeyMaterial

    @classmethod
    def for_source(cls, source_path: str, plaintext_block_digests: tuple[bytes, ...], block_size: int,
                   key_material: FileKeyMaterial) -> "UploadCheckpoint":
        source_status = os.stat(source_path)
        return cls(os.path.abspath(source_path), source_status.st_size, source_status.st_mtime_ns,
                   plaintext_block_digests, block_size, key_material)

    def looks_like_same_source(self, source_path: str) -> bool:
        # Filtro rápido; antes de reutilizar la clave se comparan además las huellas de cada bloque
        source_status = os.stat(source_path)
        return (self.source_path == os.path.abspath(source_path)
                and self.source_size == source_status.st_size
                and self.source_modified_ns == source_status.st_mtime_ns)

    def to_json_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "source_size": self.source_size,
            "source_modified_ns": self.source_modified_ns,
            "plaintext_block_digests": [digest.hex() for digest in self.plaintext_block_digests],
            "block_size": self.block_size,
            "file_id": self.key_material.file_id.hex(),
            "content_version": self.key_material.content_version,
            "data_encryption_key": to_base64(self.key_material.data_encryption_key),
            "nonce_prefix": to_base64(self.key_material.nonce_prefix),
        }

    @classmethod
    def from_json_dict(cls, data: dict) -> "UploadCheckpoint":
        key_material = FileKeyMaterial(
            file_id=from_hex(require_field(data, "file_id", str), FILE_ID_SIZE),
            content_version=require_field(data, "content_version", int),
            data_encryption_key=from_base64(require_field(data, "data_encryption_key", str)),
            nonce_prefix=from_base64(require_field(data, "nonce_prefix", str), NONCE_PREFIX_SIZE),
        )
        return cls(
            source_path=require_field(data, "source_path", str),
            source_size=require_field(data, "source_size", int),
            source_modified_ns=require_field(data, "source_modified_ns", int),
            plaintext_block_digests=tuple(
                bytes.fromhex(digest) for digest in require_field(data, "plaintext_block_digests", list)),
            block_size=require_field(data, "block_size", int),
            key_material=key_material,
        )


class UploadCheckpointStore:
    def __init__(self, directory: str, encryption_private_key: bytes):
        self._directory = directory
        # El punto de control guarda la clave de datos: se cifra con una subclave de la identidad del usuario
        self._cipher = AuthenticatedCipher(derive_subkey(encryption_private_key, _CHECKPOINT_KEY_LABEL))

    def save(self, checkpoint: UploadCheckpoint) -> None:
        nonce = random_bytes(AEAD_NONCE_SIZE)
        encrypted = self._cipher.encrypt(nonce, canonical_json(checkpoint.to_json_dict()), _CHECKPOINT_ASSOCIATED_DATA)
        write_file_atomically(self._path_for(checkpoint.key_material), nonce + encrypted, permissions=0o600)

    def find_for_source(self, source_path: str) -> list[UploadCheckpoint]:
        if not os.path.isdir(self._directory):
            return []
        checkpoints = (self._load(os.path.join(self._directory, file_name))
                       for file_name in sorted(os.listdir(self._directory)))
        return [checkpoint for checkpoint in checkpoints
                if checkpoint is not None and checkpoint.looks_like_same_source(source_path)]

    def delete(self, checkpoint: UploadCheckpoint) -> None:
        path = self._path_for(checkpoint.key_material)
        if os.path.exists(path):
            os.remove(path)

    def _load(self, path: str) -> UploadCheckpoint | None:
        try:
            with open(path, "rb") as checkpoint_file:
                raw = checkpoint_file.read()
            content = self._cipher.decrypt(raw[:AEAD_NONCE_SIZE], raw[AEAD_NONCE_SIZE:], _CHECKPOINT_ASSOCIATED_DATA)
            return UploadCheckpoint.from_json_dict(json.loads(content))
        except (OSError, ValueError, VerificationError, FormatError):
            # Puntos de control ilegibles o de otra identidad se ignoran
            return None

    def _path_for(self, key_material: FileKeyMaterial) -> str:
        return os.path.join(self._directory, f"{key_material.file_id.hex()}-v{key_material.content_version}")
