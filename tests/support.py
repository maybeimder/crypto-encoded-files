# Cifrar y descifrar un archivo en memoria, sin servidor
import os
from dataclasses import dataclass

from cryptostore.client.private_identity import PrivateIdentity
from cryptostore.protocol.file_blocks import FileKeyMaterial, SourceFileEncryptor
from cryptostore.protocol.file_metadata import FileMetadata
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.verified_download import VerifiedFileAssembler

SMALL_BLOCK_SIZE = 1024


@dataclass
class EncryptedUpload:
    key_material: FileKeyMaterial
    manifest: SignedManifest
    blocks: list[bytes]


def encrypt_for_test(source_path: str, owner: PrivateIdentity, block_size: int = SMALL_BLOCK_SIZE,
                     key_material: FileKeyMaterial | None = None) -> EncryptedUpload:
    key_material = key_material or FileKeyMaterial.generate()
    encrypted_blocks = list(SourceFileEncryptor(source_path, key_material, block_size).encrypted_blocks())
    metadata = FileMetadata(os.path.basename(source_path), "application/octet-stream", os.path.getsize(source_path))
    manifest = SignedManifest.build(
        key_material=key_material,
        owner_id=owner.user_id,
        owner_signing_private_key=owner.signing_private_key,
        block_size=block_size,
        block_hashes=[block.digest for block in encrypted_blocks],
        encrypted_metadata=metadata.encrypt(key_material),
    )
    return EncryptedUpload(key_material, manifest, [block.payload for block in encrypted_blocks])


def decrypt_for_test(manifest: SignedManifest, blocks: list[bytes], data_encryption_key: bytes,
                     owner: PrivateIdentity, destination_path, minimum_content_version: int = 0) -> None:
    body = manifest.verify(owner.public, minimum_content_version)
    key_material = body.key_material_with(data_encryption_key)
    metadata = FileMetadata.decrypt(key_material, body.encrypted_metadata)

    def fetch_block(index: int) -> bytes:
        return blocks[index] if index < len(blocks) else b""

    VerifiedFileAssembler(body, key_material, metadata.plaintext_size).assemble(fetch_block, str(destination_path))
