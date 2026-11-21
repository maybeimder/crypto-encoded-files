import mimetypes
import os
from dataclasses import dataclass, field

from cryptostore.client.access_manager import AccessManager
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.client.upload_checkpoint import UploadCheckpoint, UploadCheckpointStore
from cryptostore.errors import CryptoStoreError, FormatError, IdentityError
from cryptostore.protocol.file_blocks import (
    DEFAULT_BLOCK_SIZE,
    FileKeyMaterial,
    SourceFileEncryptor,
    plaintext_block_digests,
)
from cryptostore.protocol.file_metadata import FileMetadata
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.verified_download import ProgressCallback

_DEFAULT_MIME_TYPE = "application/octet-stream"


@dataclass(frozen=True)
class UploadResult:
    file_id: str
    content_version: int
    total_blocks: int
    blocks_already_on_server: int
    renewed_recipients: list[str] = field(default_factory=list)
    skipped_recipients: list[str] = field(default_factory=list)


class FileUploader:
    def __init__(self, session: ClientSession, on_progress: ProgressCallback | None = None):
        self._session = session
        self._on_progress = on_progress
        self._checkpoints = UploadCheckpointStore(session.workspace.checkpoints_directory,
                                                  session.identity.encryption_private_key)

    def upload(self, source_path: str, *, replace_file_id: str | None = None,
               block_size: int = DEFAULT_BLOCK_SIZE) -> UploadResult:
        target_file_id, target_version = self._choose_target(replace_file_id)
        checkpoint = (self._checkpoint_to_resume(source_path, target_file_id, target_version)
                      or self._start_new_checkpoint(source_path, target_file_id, target_version, block_size))

        encryptor = SourceFileEncryptor(source_path, checkpoint.key_material, checkpoint.block_size)
        block_hashes, blocks_already_on_server = self._send_blocks(encryptor, checkpoint)
        manifest = self._publish_manifest(source_path, encryptor, checkpoint, block_hashes)

        data_encryption_key = checkpoint.key_material.data_encryption_key
        access_manager = AccessManager(self._session)
        access_manager.grant_to_self(manifest, data_encryption_key)
        renewed, skipped = ([], []) if replace_file_id is None else \
            access_manager.renew_after_new_version(manifest, data_encryption_key)

        # Publicada la versión, el punto de control (que contiene la clave) ya no hace falta
        self._checkpoints.delete(checkpoint)
        file_id = manifest.body.file_id.hex()
        self._session.workspace.record_seen_version(file_id, manifest.body.content_version)
        return UploadResult(file_id, manifest.body.content_version, encryptor.total_blocks,
                            blocks_already_on_server, renewed, skipped)

    def _choose_target(self, replace_file_id: str | None) -> tuple[str | None, int]:
        if replace_file_id is None:
            return None, 1
        published_version = self._published_version(replace_file_id, require_owner=True)
        if published_version == 0:
            raise FormatError("ese archivo aún no tiene una versión publicada que reemplazar")
        # Mismo id de archivo, versión siguiente
        return replace_file_id, published_version + 1

    def _checkpoint_to_resume(self, source_path: str, target_file_id: str | None,
                              target_version: int) -> UploadCheckpoint | None:
        for checkpoint in self._checkpoints.find_for_source(source_path):
            key_material = checkpoint.key_material
            file_id = key_material.file_id.hex()
            same_target = (key_material.content_version == target_version
                           and (target_file_id is None or file_id == target_file_id))
            if not same_target:
                continue
            # Si esa versión ya se publicó (se perdió la respuesta), no se reanuda: se empieza otra carga
            if self._published_version(file_id) >= key_material.content_version:
                self._checkpoints.delete(checkpoint)
                continue
            # La clave solo se reutiliza si el contenido es idéntico bloque a bloque;
            # con otro contenido se repetiría (clave, nonce) y eso filtra información
            if plaintext_block_digests(source_path, checkpoint.block_size) != checkpoint.plaintext_block_digests:
                self._checkpoints.delete(checkpoint)
                continue
            return checkpoint
        return None

    def _start_new_checkpoint(self, source_path: str, target_file_id: str | None, target_version: int,
                              block_size: int) -> UploadCheckpoint:
        file_id_bytes = bytes.fromhex(target_file_id) if target_file_id else None
        key_material = FileKeyMaterial.generate(file_id_bytes, target_version)
        checkpoint = UploadCheckpoint.for_source(
            source_path, plaintext_block_digests(source_path, block_size), block_size, key_material)
        # Se guarda antes de enviar nada: si la carga se corta se retoma con esta misma clave
        self._checkpoints.save(checkpoint)
        return checkpoint

    def _send_blocks(self, encryptor: SourceFileEncryptor, checkpoint: UploadCheckpoint) -> tuple[list[bytes], int]:
        key_material = checkpoint.key_material
        file_id, version = key_material.file_id.hex(), key_material.content_version
        expected_plaintext = checkpoint.plaintext_block_digests
        if encryptor.total_blocks != len(expected_plaintext):
            self._discard_changed_source(checkpoint)
        already_on_server = self._session.server_api.list_uploaded_blocks(file_id, version)

        block_hashes, blocks_already_on_server = [], 0
        for block in encryptor.encrypted_blocks():
            # Se comprueba antes de enviar: un bloque cambiado nunca sale cifrado con la clave anterior
            if block.plaintext_digest != expected_plaintext[block.index]:
                self._discard_changed_source(checkpoint)
            block_hashes.append(block.digest)
            # Mismo texto, misma clave y misma posición dan el mismo cifrado: si el servidor ya lo tiene, se salta
            if already_on_server.get(block.index) == block.digest.hex():
                blocks_already_on_server += 1
            else:
                self._session.server_api.put_block(file_id, version, block.index, block.payload)
            if self._on_progress:
                self._on_progress(block.index + 1, encryptor.total_blocks)
        return block_hashes, blocks_already_on_server

    def _publish_manifest(self, source_path: str, encryptor: SourceFileEncryptor, checkpoint: UploadCheckpoint,
                          block_hashes: list[bytes]) -> SignedManifest:
        key_material = checkpoint.key_material
        mime_type = mimetypes.guess_type(source_path)[0] or _DEFAULT_MIME_TYPE
        metadata = FileMetadata(os.path.basename(source_path), mime_type, encryptor.file_size)
        manifest = SignedManifest.build(
            key_material=key_material,
            owner_id=self._session.identity.user_id,
            owner_signing_private_key=self._session.identity.signing_private_key,
            block_size=checkpoint.block_size,
            block_hashes=block_hashes,
            encrypted_metadata=metadata.encrypt(key_material),
        )
        try:
            self._session.server_api.commit_manifest(manifest)
            return manifest
        except ServerError as error:
            # Si se perdió la respuesta de un intento anterior, la versión puede estar ya publicada con estos bloques
            published = self._already_published_equivalent(manifest) if error.status_code == 409 else None
            if published is None:
                raise
            return published

    def _already_published_equivalent(self, manifest: SignedManifest) -> SignedManifest | None:
        body = manifest.body
        try:
            published = self._session.server_api.get_manifest(body.file_id.hex(), body.content_version)
            published.verify(self._session.identity.public)
        except (ServerError, CryptoStoreError):
            return None
        return published if published.body.block_hashes == body.block_hashes else None

    def _published_version(self, file_id: str, require_owner: bool = False) -> int:
        for listed_file in self._session.server_api.list_files():
            if listed_file["file_id"] == file_id:
                if require_owner and listed_file["role"] != "owner":
                    raise IdentityError("solo el dueño puede publicar versiones nuevas de este archivo")
                return listed_file["latest_version"]
        if require_owner:
            raise IdentityError("ese archivo no existe o no es suyo")
        return 0

    def _discard_changed_source(self, checkpoint: UploadCheckpoint) -> None:
        self._checkpoints.delete(checkpoint)
        raise FormatError("el archivo cambió durante la carga; vuelva a ejecutar la subida")
