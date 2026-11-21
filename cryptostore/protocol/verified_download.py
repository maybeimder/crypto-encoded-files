import os
import tempfile
from typing import Callable

from cryptostore.errors import VerificationError
from cryptostore.primitives.symmetric import sha256
from cryptostore.protocol.file_blocks import FileBlockCipher, FileKeyMaterial, maximum_encrypted_block_size
from cryptostore.protocol.manifest import ManifestBody

FetchBlock = Callable[[int], bytes]
ProgressCallback = Callable[[int, int], None]


# Reconstruye un archivo descargado con política fail-stop (decisión D8)
class VerifiedFileAssembler:
    def __init__(
        self,
        manifest_body: ManifestBody,
        key_material: FileKeyMaterial,
        expected_plaintext_size: int,
        on_progress: ProgressCallback | None = None,
    ):
        self._manifest_body = manifest_body
        self._block_cipher = FileBlockCipher(key_material, manifest_body.total_blocks)
        self._expected_plaintext_size = expected_plaintext_size
        self._on_progress = on_progress
        self._total_steps = 2 * manifest_body.total_blocks

    def assemble(self, fetch_block: FetchBlock, destination_path: str) -> None:
        destination_directory = os.path.dirname(os.path.abspath(destination_path))
        # Todo se prepara en una carpeta oculta junto al destino; si algo falla se borra entera
        with tempfile.TemporaryDirectory(dir=destination_directory, prefix=".descarga-") as staging_directory:
            self._download_and_check_every_block(fetch_block, staging_directory)
            plaintext_path = self._decrypt_blocks_into_single_file(staging_directory)
            # Solo con todo verificado aparece el archivo en el destino, en un único paso
            os.replace(plaintext_path, destination_path)

    def _download_and_check_every_block(self, fetch_block: FetchBlock, staging_directory: str) -> None:
        for index, expected_hash in enumerate(self._manifest_body.block_hashes):
            payload = fetch_block(index)
            self._require_expected_length(index, payload)
            # La huella debe coincidir con la que firmó el dueño en el manifiesto
            if sha256(payload) != expected_hash:
                raise VerificationError(f"bloque {index}: la huella no coincide con el manifiesto")
            with open(self._staged_block_path(staging_directory, index), "wb") as staged_block:
                staged_block.write(payload)
            self._report_progress(index + 1)

    def _decrypt_blocks_into_single_file(self, staging_directory: str) -> str:
        plaintext_path = os.path.join(staging_directory, "texto-plano")
        written_bytes = 0
        with open(plaintext_path, "wb") as plaintext_file:
            for index in range(self._manifest_body.total_blocks):
                with open(self._staged_block_path(staging_directory, index), "rb") as staged_block:
                    # Además de la huella, cada bloque debe descifrar en su posición exacta
                    plaintext = self._block_cipher.decrypt_block(index, staged_block.read())
                plaintext_file.write(plaintext)
                written_bytes += len(plaintext)
                self._report_progress(self._manifest_body.total_blocks + index + 1)
        if written_bytes != self._expected_plaintext_size:
            raise VerificationError("el tamaño reconstruido no coincide con el declarado en los metadatos")
        return plaintext_path

    def _require_expected_length(self, index: int, payload: bytes) -> None:
        full_block_length = maximum_encrypted_block_size(self._manifest_body.block_size)
        is_last_block = index == self._manifest_body.total_blocks - 1
        # Todos los bloques vienen llenos salvo el último, que puede ser más corto
        if len(payload) > full_block_length or (not is_last_block and len(payload) != full_block_length):
            raise VerificationError(f"bloque {index}: longitud inesperada")

    @staticmethod
    def _staged_block_path(staging_directory: str, index: int) -> str:
        return os.path.join(staging_directory, f"bloque-{index}")

    def _report_progress(self, completed_steps: int) -> None:
        if self._on_progress:
            self._on_progress(completed_steps, self._total_steps)
