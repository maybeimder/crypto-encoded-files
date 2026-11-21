import os
from dataclasses import dataclass

from cryptostore.client.file_version_resolver import FileVersionResolver
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.errors import VerificationError
from cryptostore.protocol.file_metadata import FileMetadata
from cryptostore.protocol.verified_download import ProgressCallback, VerifiedFileAssembler

_FALLBACK_FILE_NAME = "archivo-descargado"


@dataclass(frozen=True)
class DownloadResult:
    destination_path: str
    metadata: FileMetadata
    content_version: int


class FileDownloader:
    def __init__(self, session: ClientSession, on_progress: ProgressCallback | None = None):
        self._session = session
        self._on_progress = on_progress

    def download(self, file_id: str, destination: str | None = None, *, overwrite: bool = False) -> DownloadResult:
        resolved = FileVersionResolver(self._session).resolve(file_id)
        destination_path = _final_destination(destination, resolved.metadata.name)
        if os.path.exists(destination_path) and not overwrite:
            raise FileExistsError(f"{destination_path} ya existe (use --overwrite para reemplazarlo)")

        version = resolved.body.content_version
        assembler = VerifiedFileAssembler(resolved.body, resolved.key_material,
                                          resolved.metadata.plaintext_size, self._on_progress)
        assembler.assemble(lambda index: self._fetch_block(file_id, version, index), destination_path)
        return DownloadResult(destination_path, resolved.metadata, version)

    def _fetch_block(self, file_id: str, version: int, index: int) -> bytes:
        try:
            return self._session.server_api.get_block(file_id, version, index)
        except ServerError as error:
            # Un bloque que no llega es un archivo incompleto: se trata como fallo de verificación
            raise VerificationError(f"bloque {index}: el servidor no lo entregó ({error.status_code})") from error


def _final_destination(destination: str | None, stored_name: str) -> str:
    if destination is not None and not os.path.isdir(destination):
        return destination
    # El nombre viene de los metadatos: se usa solo su parte final para no escribir fuera de la carpeta elegida
    safe_name = os.path.basename(stored_name)
    if safe_name in ("", ".", ".."):
        safe_name = _FALLBACK_FILE_NAME
    return os.path.join(destination or ".", safe_name)
