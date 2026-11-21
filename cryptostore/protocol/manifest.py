import time
from dataclasses import dataclass
from functools import cached_property

from cryptostore.errors import FormatError, VerificationError
from cryptostore.primitives.public_key import SIGNATURE_SIZE, sign, verify_signature
from cryptostore.primitives.symmetric import SHA256_DIGEST_SIZE, sha256
from cryptostore.protocol.file_blocks import (
    FILE_ID_SIZE,
    MAXIMUM_BLOCK_SIZE,
    MAXIMUM_CONTENT_VERSION,
    MAXIMUM_FILE_SIZE,
    MINIMUM_BLOCK_SIZE,
    NONCE_PREFIX_SIZE,
    FileKeyMaterial,
    count_blocks,
)
from cryptostore.protocol.public_identity import FINGERPRINT_HEX_LENGTH, PublicIdentity
from cryptostore.protocol.serialization import (
    canonical_json,
    from_base64,
    from_hex,
    require_field,
    to_base64,
)

MANIFEST_FORMAT = "p5-e2ee-store/1"
CIPHER_SUITE = "HPKE-X25519-HKDFSHA256-CHACHA20POLY1305+ED25519"
_SIGNATURE_DOMAIN = b"MANIFEST\x01"


# Descripción pública de una versión: lo necesario para reconstruirla y verificarla sin confiar en el servidor
@dataclass(frozen=True)
class ManifestBody:
    file_id: bytes
    content_version: int
    owner_id: str
    nonce_prefix: bytes
    block_size: int
    block_hashes: tuple[bytes, ...]
    encrypted_metadata: bytes
    created_at: int

    @property
    def total_blocks(self) -> int:
        return len(self.block_hashes)

    def key_material_with(self, data_encryption_key: bytes) -> FileKeyMaterial:
        # Parámetros públicos del manifiesto + la clave de datos que se sacó de la envolvente
        return FileKeyMaterial(self.file_id, self.content_version, data_encryption_key, self.nonce_prefix)

    def to_json_dict(self) -> dict:
        return {
            "format": MANIFEST_FORMAT,
            "suite": CIPHER_SUITE,
            "file_id": self.file_id.hex(),
            "content_version": self.content_version,
            "owner_id": self.owner_id,
            "nonce_prefix": to_base64(self.nonce_prefix),
            "block_size": self.block_size,
            "block_hashes": [block_hash.hex() for block_hash in self.block_hashes],
            "encrypted_metadata": to_base64(self.encrypted_metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_json_dict(cls, data: dict) -> "ManifestBody":
        if require_field(data, "format", str) != MANIFEST_FORMAT or require_field(data, "suite", str) != CIPHER_SUITE:
            raise FormatError("formato o suite criptográfica no soportados")
        body = cls(
            file_id=from_hex(require_field(data, "file_id", str), FILE_ID_SIZE),
            content_version=require_field(data, "content_version", int),
            owner_id=require_field(data, "owner_id", str),
            nonce_prefix=from_base64(require_field(data, "nonce_prefix", str), NONCE_PREFIX_SIZE),
            block_size=require_field(data, "block_size", int),
            block_hashes=tuple(
                from_hex(block_hash, SHA256_DIGEST_SIZE) for block_hash in require_field(data, "block_hashes", list)
            ),
            encrypted_metadata=from_base64(require_field(data, "encrypted_metadata", str)),
            created_at=require_field(data, "created_at", int),
        )
        body._require_sane_values()
        return body

    def _require_sane_values(self) -> None:
        if not 1 <= self.content_version <= MAXIMUM_CONTENT_VERSION:
            raise FormatError("versión fuera de rango")
        if len(self.owner_id) != FINGERPRINT_HEX_LENGTH:
            raise FormatError("id de dueño inválido")
        if not MINIMUM_BLOCK_SIZE <= self.block_size <= MAXIMUM_BLOCK_SIZE:
            raise FormatError("tamaño de bloque fuera de rango")
        if not 1 <= self.total_blocks <= count_blocks(MAXIMUM_FILE_SIZE, self.block_size):
            raise FormatError("número de bloques fuera de rango")


# Manifiesto + firma Ed25519 del dueño. Inmutable: compartir o revocar no lo toca (decisión D3)
@dataclass(frozen=True)
class SignedManifest:
    body: ManifestBody
    signature: bytes

    @classmethod
    def create(cls, body: ManifestBody, owner_signing_private_key: bytes) -> "SignedManifest":
        signature = sign(owner_signing_private_key, _SIGNATURE_DOMAIN, canonical_json(body.to_json_dict()))
        return cls(body, signature)

    @classmethod
    def build(
        cls,
        *,
        key_material: FileKeyMaterial,
        owner_id: str,
        owner_signing_private_key: bytes,
        block_size: int,
        block_hashes: list[bytes],
        encrypted_metadata: bytes,
    ) -> "SignedManifest":
        body = ManifestBody(
            file_id=key_material.file_id,
            content_version=key_material.content_version,
            owner_id=owner_id,
            nonce_prefix=key_material.nonce_prefix,
            block_size=block_size,
            block_hashes=tuple(block_hashes),
            encrypted_metadata=encrypted_metadata,
            created_at=int(time.time()),
        )
        return cls.create(body, owner_signing_private_key)

    @cached_property
    def digest(self) -> bytes:
        # Las envolventes quedan atadas a esta huella exacta del manifiesto (decisión D4)
        return sha256(canonical_json(self.to_json_dict()))

    def verify(self, owner: PublicIdentity, minimum_content_version: int = 0) -> ManifestBody:
        # 1. Debe declarar como dueño a la identidad que el cliente tiene fijada localmente
        if self.body.owner_id != owner.user_id:
            raise VerificationError("el manifiesto no pertenece al dueño esperado")
        # 2. La firma de ese dueño debe cubrir el contenido exacto: el servidor no puede alterarlo ni fabricarlo
        verify_signature(
            owner.signing_public_key, _SIGNATURE_DOMAIN, canonical_json(self.body.to_json_dict()), self.signature
        )
        # 3. No se acepta una versión anterior a la última ya vista (el servidor no puede retroceder)
        if self.body.content_version < minimum_content_version:
            raise VerificationError("el servidor entregó una versión anterior a la ya conocida")
        return self.body

    def to_json_dict(self) -> dict:
        return {"body": self.body.to_json_dict(), "signature": to_base64(self.signature)}

    @classmethod
    def from_json_dict(cls, data: dict) -> "SignedManifest":
        return cls(
            body=ManifestBody.from_json_dict(require_field(data, "body", dict)),
            signature=from_base64(require_field(data, "signature", str), SIGNATURE_SIZE),
        )
