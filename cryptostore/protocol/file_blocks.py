import os
import struct
from dataclasses import dataclass
from functools import cached_property
from typing import Iterator

from cryptostore.errors import FormatError, VerificationError
from cryptostore.primitives.symmetric import (
    AEAD_TAG_SIZE,
    SYMMETRIC_KEY_SIZE,
    AuthenticatedCipher,
    derive_subkey,
    random_bytes,
    sha256,
)

DEFAULT_BLOCK_SIZE = 1 << 20
MINIMUM_BLOCK_SIZE = 1 << 10
MAXIMUM_BLOCK_SIZE = 4 << 20
MAXIMUM_FILE_SIZE = 100 << 20
MAXIMUM_CONTENT_VERSION = 2**32 - 1
FILE_ID_SIZE = 16
NONCE_PREFIX_SIZE = 4

_BLOCK_ASSOCIATED_DATA_TAG = b"BLK\x01"
_BLOCK_KEY_LABEL = b"p5/blocks/v1"
_METADATA_KEY_LABEL = b"p5/meta/v1"


def count_blocks(file_size: int, block_size: int) -> int:
    # Un archivo vacío ocupa un bloque de 0 bytes (decisión D7)
    return max(1, -(-file_size // block_size))


def maximum_encrypted_block_size(block_size: int) -> int:
    return block_size + AEAD_TAG_SIZE


@dataclass(frozen=True)
class FileKeyMaterial:
    file_id: bytes
    content_version: int
    data_encryption_key: bytes
    nonce_prefix: bytes

    def __post_init__(self):
        if len(self.file_id) != FILE_ID_SIZE:
            raise FormatError("el id de archivo debe tener 16 bytes")
        if len(self.data_encryption_key) != SYMMETRIC_KEY_SIZE:
            raise FormatError("la clave de datos debe tener 32 bytes")
        if len(self.nonce_prefix) != NONCE_PREFIX_SIZE:
            raise FormatError("el prefijo de nonce debe tener 4 bytes")
        if not 1 <= self.content_version <= MAXIMUM_CONTENT_VERSION:
            raise FormatError("versión de contenido fuera de rango")

    @classmethod
    def generate(cls, file_id: bytes | None = None, content_version: int = 1) -> "FileKeyMaterial":
        # Clave de datos (DEK) y prefijo de nonce nuevos en cada versión: así la pareja
        # (clave, nonce) nunca se repite aunque el archivo se vuelva a subir (decisión D5)
        return cls(
            file_id=file_id if file_id is not None else random_bytes(FILE_ID_SIZE),
            content_version=content_version,
            data_encryption_key=random_bytes(SYMMETRIC_KEY_SIZE),
            nonce_prefix=random_bytes(NONCE_PREFIX_SIZE),
        )

    @cached_property
    def block_key(self) -> bytes:
        # Subclave exclusiva para bloques; los metadatos usan otra (decisión D6)
        return derive_subkey(self.data_encryption_key, _BLOCK_KEY_LABEL)

    @cached_property
    def metadata_key(self) -> bytes:
        return derive_subkey(self.data_encryption_key, _METADATA_KEY_LABEL)


@dataclass(frozen=True)
class EncryptedBlock:
    index: int
    payload: bytes            # cifrado + etiqueta de 16 B
    plaintext_digest: bytes   # huella del texto plano; solo la usa el cliente local, nunca se envía

    @cached_property
    def digest(self) -> bytes:
        return sha256(self.payload)


class FileBlockCipher:
    def __init__(self, key_material: FileKeyMaterial, total_blocks: int):
        if total_blocks < 1:
            raise FormatError("un archivo tiene al menos un bloque")
        self._key_material = key_material
        self._total_blocks = total_blocks
        self._cipher = AuthenticatedCipher(key_material.block_key)

    def encrypt_block(self, index: int, plaintext: bytes) -> EncryptedBlock:
        self._require_valid_index(index)
        payload = self._cipher.encrypt(self._nonce_for(index), plaintext, self._associated_data_for(index))
        return EncryptedBlock(index, payload, sha256(plaintext))

    def decrypt_block(self, index: int, payload: bytes) -> bytes:
        self._require_valid_index(index)
        if len(payload) < AEAD_TAG_SIZE:
            raise VerificationError(f"bloque {index}: demasiado corto para contener la etiqueta")
        # Solo descifra si el bloque fue cifrado para esta misma posición, archivo y versión
        return self._cipher.decrypt(self._nonce_for(index), payload, self._associated_data_for(index))

    def _nonce_for(self, index: int) -> bytes:
        # Prefijo aleatorio de la versión (4 B) + índice del bloque (8 B): nunca se repite dentro de la versión
        return self._key_material.nonce_prefix + struct.pack(">Q", index)

    def _associated_data_for(self, index: int) -> bytes:
        # Marcar el último bloque impide truncar el archivo quitando bloques del final
        is_last_block = 1 if index == self._total_blocks - 1 else 0
        # 33 B: "BLK\x01" | id archivo (16) | versión (4) | índice (4) | total (4) | ¿último? (1).
        # Un bloque movido, duplicado o de otro archivo/versión no coincide con esto y no descifra
        return (
            _BLOCK_ASSOCIATED_DATA_TAG
            + self._key_material.file_id
            + struct.pack(">III", self._key_material.content_version, index, self._total_blocks)
            + bytes([is_last_block])
        )

    def _require_valid_index(self, index: int) -> None:
        if not 0 <= index < self._total_blocks:
            raise VerificationError(f"índice de bloque {index} fuera de rango")


class SourceFileEncryptor:
    def __init__(self, source_path: str, key_material: FileKeyMaterial, block_size: int = DEFAULT_BLOCK_SIZE):
        if not MINIMUM_BLOCK_SIZE <= block_size <= MAXIMUM_BLOCK_SIZE:
            raise FormatError("tamaño de bloque fuera de rango")
        self.source_path = source_path
        self.block_size = block_size
        self.file_size = os.path.getsize(source_path)
        if self.file_size > MAXIMUM_FILE_SIZE:
            raise FormatError("el archivo supera el límite de 100 MiB")
        self.total_blocks = count_blocks(self.file_size, block_size)
        self._block_cipher = FileBlockCipher(key_material, self.total_blocks)

    def encrypted_blocks(self) -> Iterator[EncryptedBlock]:
        bytes_read = 0
        with open(self.source_path, "rb") as source_file:
            # Bloque a bloque: nunca se carga el archivo completo en memoria
            for index in range(self.total_blocks):
                plaintext = source_file.read(self.block_size)
                bytes_read += len(plaintext)
                yield self._block_cipher.encrypt_block(index, plaintext)
            source_file_grew = source_file.read(1) != b""
        # Si el archivo cambió mientras se leía, el manifiesto describiría algo que ya no existe
        if source_file_grew or bytes_read != self.file_size:
            raise FormatError("el archivo cambió mientras se cifraba")


def plaintext_block_digests(source_path: str, block_size: int) -> tuple[bytes, ...]:
    total_blocks = count_blocks(os.path.getsize(source_path), block_size)
    with open(source_path, "rb") as source_file:
        # Huella del texto plano de cada bloque, para saber si el contenido cambió entre intentos
        return tuple(sha256(source_file.read(block_size)) for _ in range(total_blocks))
