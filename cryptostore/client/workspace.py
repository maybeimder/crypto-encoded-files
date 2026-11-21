import json
import os
from dataclasses import asdict, dataclass

from cryptostore.atomic_files import write_file_atomically
from cryptostore.errors import IdentityError
from cryptostore.protocol.serialization import canonical_json


@dataclass(frozen=True)
class SessionInfo:
    server_url: str
    user_id: str
    token: str


# Carpeta local de un usuario: identidad, libreta, sesión, versiones vistas y cargas pendientes
class ClientWorkspace:
    def __init__(self, home_directory: str):
        self.home_directory = os.path.abspath(os.path.expanduser(home_directory))

    @property
    def identity_path(self) -> str:
        return os.path.join(self.home_directory, "identity.json")

    @property
    def trust_store_path(self) -> str:
        return os.path.join(self.home_directory, "trust-store.json")

    @property
    def checkpoints_directory(self) -> str:
        return os.path.join(self.home_directory, "pending-uploads")

    @property
    def _session_path(self) -> str:
        return os.path.join(self.home_directory, "session.json")

    @property
    def _seen_versions_path(self) -> str:
        return os.path.join(self.home_directory, "seen-versions.json")

    def is_initialized(self) -> bool:
        return os.path.exists(self.identity_path)

    def save_session(self, session_info: SessionInfo) -> None:
        # Contiene el token de sesión: solo legible por el usuario
        write_file_atomically(self._session_path, canonical_json(asdict(session_info)), permissions=0o600)

    def load_session(self) -> SessionInfo:
        if not os.path.exists(self._session_path):
            raise IdentityError(f"no hay sesión en {self.home_directory}: ejecute primero 'init'")
        with open(self._session_path, "rb") as session_file:
            return SessionInfo(**json.loads(session_file.read()))

    def seen_version(self, file_id: str) -> int:
        return self._load_seen_versions().get(file_id, 0)

    def record_seen_version(self, file_id: str, content_version: int) -> None:
        seen_versions = self._load_seen_versions()
        # Solo sube: así un servidor no puede hacer volver al cliente a una versión vieja
        if content_version > seen_versions.get(file_id, 0):
            seen_versions[file_id] = content_version
            write_file_atomically(self._seen_versions_path, canonical_json(seen_versions))

    def _load_seen_versions(self) -> dict[str, int]:
        if not os.path.exists(self._seen_versions_path):
            return {}
        with open(self._seen_versions_path, "rb") as seen_file:
            return json.loads(seen_file.read())
