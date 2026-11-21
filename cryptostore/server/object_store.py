import json
import os
import re
import threading
from dataclasses import asdict, dataclass

from cryptostore.atomic_files import write_file_atomically
from cryptostore.errors import FormatError, VerificationError
from cryptostore.primitives.symmetric import sha256
from cryptostore.protocol.access_grant import AccessGrant
from cryptostore.protocol.file_blocks import (
    MAXIMUM_BLOCK_SIZE,
    MAXIMUM_CONTENT_VERSION,
    MAXIMUM_FILE_SIZE,
    MINIMUM_BLOCK_SIZE,
    count_blocks,
    maximum_encrypted_block_size,
)
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.public_identity import PublicIdentity
from cryptostore.protocol.serialization import canonical_json

MAXIMUM_BLOCK_PAYLOAD = maximum_encrypted_block_size(MAXIMUM_BLOCK_SIZE)
MAXIMUM_BLOCKS_PER_FILE = count_blocks(MAXIMUM_FILE_SIZE, MINIMUM_BLOCK_SIZE)
_USER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_FILE_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


class StoreError(Exception):
    http_status = 400


class InvalidRequestError(StoreError):
    http_status = 400


class ForbiddenError(StoreError):
    http_status = 403


class NotFoundError(StoreError):
    http_status = 404


class ConflictError(StoreError):
    http_status = 409


@dataclass
class FileState:
    owner_id: str
    latest_version: int = 0  # 0 = aún no hay ninguna versión publicada
    acl_epoch: int = 0       # aumenta en cada alta o baja de destinatario (decisión D1)


# Guarda bytes opacos sin tener ninguna clave. Sus permisos organizan el acceso;
# la confidencialidad la da el cifrado de extremo a extremo
class ObjectStore:
    def __init__(self, root_directory: str):
        self._root = os.path.abspath(root_directory)
        self._lock = threading.RLock()
        os.makedirs(os.path.join(self._root, "users"), exist_ok=True)
        os.makedirs(os.path.join(self._root, "files"), exist_ok=True)

    # ---------- usuarios ----------

    def register_user(self, identity_data: dict) -> str:
        try:
            identity = PublicIdentity.from_json_dict(identity_data)
        except FormatError as error:
            raise InvalidRequestError(str(error)) from error
        with self._lock:
            # El id lo calcula el servidor desde las claves (es la huella); el cliente no lo elige
            path = self._user_path(identity.user_id)
            if os.path.exists(path):
                raise ConflictError("esa identidad ya está registrada")
            write_file_atomically(path, canonical_json(identity.to_json_dict()), permissions=0o644)
        return identity.user_id

    def get_user(self, user_id: str) -> dict:
        return self._load_public_identity(user_id).to_json_dict()

    def list_users(self) -> list[dict]:
        users_directory = os.path.join(self._root, "users")
        user_ids = [file_name.removesuffix(".json") for file_name in sorted(os.listdir(users_directory))
                    if file_name.endswith(".json")]
        return [{"user_id": user_id, **self.get_user(user_id)} for user_id in user_ids]

    # ---------- carga de una versión ----------

    def put_block(self, caller_id: str, file_id: str, version: int, index: int, payload: bytes) -> None:
        self._require_valid_file_id(file_id)
        self._require_valid_version(version)
        if not 0 <= index < MAXIMUM_BLOCKS_PER_FILE:
            raise InvalidRequestError("índice de bloque fuera de rango")
        if len(payload) > MAXIMUM_BLOCK_PAYLOAD:
            raise InvalidRequestError("bloque demasiado grande")

        with self._lock:
            # El primer bloque de un archivo nuevo convierte a quien lo sube en su dueño
            state = self._load_state_or_none(file_id) or self._claim_new_file(caller_id, file_id)
            self._require_owner(state, caller_id)
            # Una versión publicada no se modifica nunca; los cambios van en una versión nueva
            if version <= state.latest_version:
                raise ConflictError("esa versión ya está publicada y es inmutable")

            path = self._block_path(file_id, version, index)
            # Reenviar el mismo bloque es un reintento inofensivo; uno distinto en la misma
            # posición se rechaza porque mezclaría dos cifrados
            if os.path.exists(path):
                with open(path, "rb") as stored_block:
                    if stored_block.read() == payload:
                        return
                raise ConflictError("ya existe un bloque distinto en esa posición")
            write_file_atomically(path, payload, permissions=0o644)

    def list_uploaded_blocks(self, caller_id: str, file_id: str, version: int) -> dict[int, str]:
        with self._lock:
            self._require_owner(self._load_state(file_id), caller_id)
            blocks_directory = os.path.join(self._version_directory(file_id, version), "blocks")
            if not os.path.isdir(blocks_directory):
                return {}
            # Huella de cada bloque ya recibido: el dueño la usa para reanudar sin reenviar
            uploaded = {}
            for file_name in os.listdir(blocks_directory):
                if file_name.isdigit():
                    with open(os.path.join(blocks_directory, file_name), "rb") as stored_block:
                        uploaded[int(file_name)] = sha256(stored_block.read()).hex()
            return uploaded

    def commit_manifest(self, caller_id: str, file_id: str, version: int, manifest_data: dict) -> None:
        self._require_valid_version(version)
        try:
            manifest = SignedManifest.from_json_dict(manifest_data)
        except FormatError as error:
            raise InvalidRequestError(str(error)) from error

        with self._lock:
            state = self._load_state(file_id)
            self._require_owner(state, caller_id)
            if version <= state.latest_version:
                raise ConflictError("esa versión ya está publicada")
            # Comprobaciones de cortesía; el cliente no confía en ellas y lo repite todo al descargar
            body = manifest.body
            if body.file_id.hex() != file_id or body.content_version != version or body.owner_id != caller_id:
                raise InvalidRequestError("el manifiesto no corresponde a esta ruta o a este dueño")
            try:
                manifest.verify(self._load_public_identity(caller_id))
            except VerificationError as error:
                raise InvalidRequestError("la firma del manifiesto no es válida") from error
            self._require_all_blocks_present(file_id, version, body.block_hashes)

            write_file_atomically(self._manifest_path(file_id, version),
                                  canonical_json(manifest.to_json_dict()), permissions=0o644)
            state.latest_version = version
            self._save_state(file_id, state)

    # ---------- lectura ----------

    def get_manifest(self, caller_id: str, file_id: str, version: int | None = None) -> dict:
        with self._lock:
            state = self._require_read_access(caller_id, file_id)
            version = version or state.latest_version
            return self._read_json(self._manifest_path(file_id, version), "esa versión no existe")

    def get_block(self, caller_id: str, file_id: str, version: int, index: int) -> bytes:
        with self._lock:
            self._require_read_access(caller_id, file_id)
            if not os.path.exists(self._manifest_path(file_id, version)):
                raise NotFoundError("esa versión no está publicada")
            path = self._block_path(file_id, version, index)
            if not os.path.exists(path):
                raise NotFoundError("ese bloque no existe")
            with open(path, "rb") as stored_block:
                return stored_block.read()

    def list_files(self, caller_id: str) -> list[dict]:
        visible_files = []
        with self._lock:
            for file_id in sorted(os.listdir(os.path.join(self._root, "files"))):
                state = self._load_state_or_none(file_id)
                if state is None:
                    continue
                # Solo se listan los archivos propios y los compartidos con quien pregunta
                if state.owner_id == caller_id:
                    role = "owner"
                elif state.latest_version and os.path.exists(self._grant_path(file_id, caller_id)):
                    role = "recipient"
                else:
                    continue
                visible_files.append({"file_id": file_id, "role": role, **asdict(state)})
        return visible_files

    # ---------- envolventes de acceso ----------

    def put_grant(self, caller_id: str, file_id: str, recipient_id: str, grant_data: dict) -> int:
        try:
            grant = AccessGrant.from_json_dict(grant_data)
        except FormatError as error:
            raise InvalidRequestError(str(error)) from error

        with self._lock:
            state = self._load_state(file_id)
            self._require_owner(state, caller_id)
            if state.latest_version == 0:
                raise ConflictError("primero hay que publicar una versión")
            self._load_public_identity(recipient_id)
            if (grant.file_id.hex(), grant.recipient_id, grant.content_version) != (
                    file_id, recipient_id, state.latest_version):
                raise InvalidRequestError("la envolvente no corresponde al archivo, destinatario o última versión")

            # Compartir solo agrega este archivo pequeño: bloques y manifiesto quedan intactos
            write_file_atomically(self._grant_path(file_id, recipient_id),
                                  canonical_json(grant.to_json_dict()), permissions=0o644)
            return self._advance_acl_epoch(file_id, state)

    def delete_grant(self, caller_id: str, file_id: str, recipient_id: str) -> int:
        with self._lock:
            state = self._load_state(file_id)
            self._require_owner(state, caller_id)
            path = self._grant_path(file_id, recipient_id)
            if not os.path.exists(path):
                raise NotFoundError("ese destinatario no tiene acceso")
            # Revocar = borrar la envolvente. Lo que el destinatario ya descargó sigue en su equipo
            os.remove(path)
            return self._advance_acl_epoch(file_id, state)

    def get_own_grant(self, caller_id: str, file_id: str) -> dict:
        with self._lock:
            self._load_state(file_id)
            return self._read_json(self._grant_path(file_id, caller_id), "no tiene acceso a este archivo")

    def list_grant_recipients(self, caller_id: str, file_id: str) -> dict:
        with self._lock:
            state = self._load_state(file_id)
            self._require_owner(state, caller_id)
            grants_directory = os.path.join(self._file_directory(file_id), "grants")
            recipients = sorted(
                file_name.removesuffix(".json") for file_name in os.listdir(grants_directory)
                if file_name.endswith(".json")
            ) if os.path.isdir(grants_directory) else []
            return {"acl_epoch": state.acl_epoch, "recipient_ids": recipients}

    # ---------- reglas internas ----------

    def _claim_new_file(self, caller_id: str, file_id: str) -> FileState:
        state = FileState(owner_id=caller_id)
        self._save_state(file_id, state)
        return state

    def _advance_acl_epoch(self, file_id: str, state: FileState) -> int:
        # Contador de cambios de permisos; no está en los datos asociados de los bloques (decisión D1)
        state.acl_epoch += 1
        self._save_state(file_id, state)
        return state.acl_epoch

    def _require_owner(self, state: FileState, caller_id: str) -> None:
        if state.owner_id != caller_id:
            raise ForbiddenError("solo el dueño puede hacer esto")

    def _require_read_access(self, caller_id: str, file_id: str) -> FileState:
        state = self._load_state(file_id)
        is_owner = state.owner_id == caller_id
        if not is_owner and not os.path.exists(self._grant_path(file_id, caller_id)):
            raise ForbiddenError("no tiene acceso a este archivo")
        if state.latest_version == 0:
            raise NotFoundError("el archivo aún no tiene versiones publicadas")
        return state

    def _require_all_blocks_present(self, file_id: str, version: int, block_hashes) -> None:
        for index, expected_hash in enumerate(block_hashes):
            path = self._block_path(file_id, version, index)
            if not os.path.exists(path):
                raise InvalidRequestError(f"falta el bloque {index}")
            with open(path, "rb") as stored_block:
                if sha256(stored_block.read()) != expected_hash:
                    raise InvalidRequestError(f"el bloque {index} no coincide con el manifiesto")

    @staticmethod
    def _require_valid_file_id(file_id: str) -> None:
        if not _FILE_ID_PATTERN.fullmatch(file_id):
            raise InvalidRequestError("id de archivo inválido")

    @staticmethod
    def _require_valid_user_id(user_id: str) -> None:
        if not _USER_ID_PATTERN.fullmatch(user_id):
            raise InvalidRequestError("id de usuario inválido")

    @staticmethod
    def _require_valid_version(version: int) -> None:
        if not 1 <= version <= MAXIMUM_CONTENT_VERSION:
            raise InvalidRequestError("versión fuera de rango")

    # ---------- persistencia ----------

    def _load_public_identity(self, user_id: str) -> PublicIdentity:
        return PublicIdentity.from_json_dict(self._read_json(self._user_path(user_id), "usuario no registrado"))

    def _load_state(self, file_id: str) -> FileState:
        state = self._load_state_or_none(file_id)
        if state is None:
            raise NotFoundError("archivo no encontrado")
        return state

    def _load_state_or_none(self, file_id: str) -> FileState | None:
        self._require_valid_file_id(file_id)
        path = os.path.join(self._file_directory(file_id), "state.json")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as state_file:
            return FileState(**json.loads(state_file.read()))

    def _save_state(self, file_id: str, state: FileState) -> None:
        write_file_atomically(os.path.join(self._file_directory(file_id), "state.json"),
                              canonical_json(asdict(state)), permissions=0o644)

    @staticmethod
    def _read_json(path: str, missing_message: str) -> dict:
        if not os.path.exists(path):
            raise NotFoundError(missing_message)
        with open(path, "rb") as json_file:
            return json.loads(json_file.read())

    def _user_path(self, user_id: str) -> str:
        # Ids validados como hexadecimales: ninguna ruta puede escapar de la raíz con "../"
        self._require_valid_user_id(user_id)
        return os.path.join(self._root, "users", f"{user_id}.json")

    def _file_directory(self, file_id: str) -> str:
        self._require_valid_file_id(file_id)
        return os.path.join(self._root, "files", file_id)

    def _version_directory(self, file_id: str, version: int) -> str:
        self._require_valid_version(version)
        return os.path.join(self._file_directory(file_id), f"v{version}")

    def _block_path(self, file_id: str, version: int, index: int) -> str:
        return os.path.join(self._version_directory(file_id, version), "blocks", str(index))

    def _manifest_path(self, file_id: str, version: int) -> str:
        return os.path.join(self._version_directory(file_id, version), "manifest.json")

    def _grant_path(self, file_id: str, recipient_id: str) -> str:
        self._require_valid_user_id(recipient_id)
        return os.path.join(self._file_directory(file_id), "grants", f"{recipient_id}.json")
