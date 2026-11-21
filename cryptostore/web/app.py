import math
import os
import shutil
import uuid
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Path, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from cryptostore.client.access_manager import AccessManager, revocation_scope_message
from cryptostore.client.file_catalog import list_visible_files
from cryptostore.client.file_downloader import FileDownloader
from cryptostore.client.file_uploader import FileUploader
from cryptostore.client.private_identity import PrivateIdentity
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.client.workspace import ClientWorkspace
from cryptostore.errors import CryptoStoreError, IdentityError, VerificationError
from cryptostore.protocol.file_blocks import MAXIMUM_FILE_SIZE
from cryptostore.protocol.public_identity import format_fingerprint_for_humans, normalize_fingerprint
from cryptostore.web.jobs import JobRegistry, ProgressCallback
from cryptostore.web.network_access import IpNetwork, NetworkAccessPolicy
from cryptostore.web.user_sessions import LoggedInUser, LoginThrottle, WebSessionRegistry

SESSION_COOKIE_NAME = "cryptostore_session"
CSRF_HEADER_NAME = "x-cryptostore"
SERVER_URL_ENVIRONMENT_VARIABLE = "CRYPTOSTORE_SERVER_URL"
DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
DEFAULT_IDLE_SECONDS = 30 * 60
MAXIMUM_FAILED_LOGINS = 5
LOGIN_LOCK_SECONDS = 30
MINIMUM_PASSPHRASE_LENGTH = 8
# Minúsculas, números, guion y guion bajo: el nombre es también el de la carpeta del usuario
USERNAME_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"

_STATIC_DIRECTORY = os.path.join(os.path.dirname(__file__), "static")
_STAGING_DIRECTORY_NAME = ".web-staging"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

FileId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
Username = Annotated[str, Field(pattern=USERNAME_PATTERN)]


class RegisterRequest(BaseModel):
    username: Username
    server_url: str
    passphrase: str = Field(min_length=MINIMUM_PASSPHRASE_LENGTH)


class LoginRequest(BaseModel):
    username: Username
    passphrase: str


class PasswordConfirmation(BaseModel):
    passphrase: str


class TrustRequest(BaseModel):
    alias: str
    fingerprint: str


class ShareRequest(PasswordConfirmation):
    alias: str


class RevokeRequest(PasswordConfirmation):
    recipient: str


def create_web_app(users_directory: str, *, http_client: httpx.Client | None = None,
                   allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS,
                   allowed_networks: list[IpNetwork] | None = None,
                   secure_cookies: bool = False,
                   idle_seconds: float = DEFAULT_IDLE_SECONDS) -> FastAPI:
    users_directory = os.path.abspath(os.path.expanduser(users_directory))
    os.makedirs(users_directory, mode=0o700, exist_ok=True)
    staging_root = os.path.join(users_directory, _STAGING_DIRECTORY_NAME)
    # Restos de una ejecución anterior (archivos en claro a medio entregar) se borran al arrancar
    shutil.rmtree(staging_root, ignore_errors=True)

    sessions = WebSessionRegistry(idle_seconds)
    throttle = LoginThrottle(MAXIMUM_FAILED_LOGINS, LOGIN_LOCK_SECONDS)
    jobs = JobRegistry()
    app = FastAPI(title="cryptostore — interfaz local", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=_STATIC_DIRECTORY), name="static")
    _register_error_handlers(app)
    access_policy = NetworkAccessPolicy(allowed_networks, allowed_hosts)

    @app.middleware("http")
    async def restrict_network_access(request: Request, call_next):
        client_address = request.client.host if request.client else None
        # Solo los equipos de las redes autorizadas llegan siquiera a ver la página de entrada
        if not access_policy.client_allowed(client_address):
            return PlainTextResponse("equipo no autorizado para esta interfaz", status_code=403)
        # Bloquea "DNS rebinding": una web ajena que apunte su dominio a esta máquina no pasa este control
        if not access_policy.host_header_allowed(request.headers.get("host", "")):
            return PlainTextResponse("host no permitido", status_code=403)
        return await call_next(request)

    def home_of(username: str) -> str:
        return os.path.join(users_directory, username)

    def require_interface_request(request: Request) -> None:
        # Una página ajena no puede añadir cabeceras propias sin permiso del navegador: frena peticiones forjadas
        if request.method not in _SAFE_METHODS and request.headers.get(CSRF_HEADER_NAME) != "1":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "petición sin la cabecera de la interfaz")

    def require_user(request: Request, _local: None = Depends(require_interface_request)) -> LoggedInUser:
        user = sessions.find(request.cookies.get(SESSION_COOKIE_NAME))
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "inicie sesión")
        return user

    def start_session(response: Response, username: str, client_session: ClientSession) -> dict:
        session_id = sessions.open(username, client_session)
        # Con HTTPS la cookie se marca "secure": nunca viaja por una conexión sin cifrar
        response.set_cookie(SESSION_COOKIE_NAME, session_id, httponly=True, samesite="strict", secure=secure_cookies)
        return describe(sessions.find(session_id))

    def describe(user: LoggedInUser | None) -> dict:
        content = {"logged_in": user is not None,
                   # En Docker el servidor no está en 127.0.0.1; la URL sugerida llega por entorno
                   "suggested_server_url": os.environ.get(SERVER_URL_ENVIRONMENT_VARIABLE, "http://127.0.0.1:8000")}
        if user is not None:
            session = user.client_session
            content.update(username=user.username, user_id=session.identity.user_id,
                           fingerprint=format_fingerprint_for_humans(session.identity.user_id),
                           server_url=session.workspace.load_session().server_url,
                           home_directory=session.workspace.home_directory)
        return content

    def confirm_password(user: LoggedInUser, passphrase: str) -> None:
        require_not_throttled(user.username)
        # Se vuelve a abrir la identidad: actúa quien sabe la contraseña, no cualquiera con la pestaña abierta
        try:
            confirmed = PrivateIdentity.load(user.client_session.workspace.identity_path, passphrase)
        except IdentityError:
            throttle.record_failure(user.username)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "contraseña incorrecta: no se hizo nada")
        if confirmed.user_id != user.client_session.identity.user_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "la identidad cambió en disco: vuelva a entrar")
        throttle.record_success(user.username)

    def require_not_throttled(username: str) -> None:
        wait_seconds = throttle.seconds_locked(username)
        if wait_seconds:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                f"demasiados intentos fallidos: espere {math.ceil(wait_seconds)} s")

    def new_staging_directory() -> str:
        directory = os.path.join(staging_root, uuid.uuid4().hex)
        os.makedirs(directory, mode=0o700)
        return directory

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(_STATIC_DIRECTORY, "index.html"))

    # ---------- cuenta ----------

    @app.get("/api/status", dependencies=[Depends(require_interface_request)])
    def get_status(request: Request):
        return describe(sessions.find(request.cookies.get(SESSION_COOKIE_NAME)))

    @app.post("/api/register", dependencies=[Depends(require_interface_request)])
    def register(request: RegisterRequest, response: Response):
        if ClientWorkspace(home_of(request.username)).is_initialized():
            raise HTTPException(status.HTTP_409_CONFLICT, "ese usuario ya existe en este equipo")
        # Crear cuenta = generar las claves aquí, registrar solo la parte pública y cifrar la privada con la contraseña
        client_session = ClientSession.create(home_of(request.username), request.username, request.passphrase,
                                              request.server_url, http_client=http_client)
        return start_session(response, request.username, client_session)

    @app.post("/api/login", dependencies=[Depends(require_interface_request)])
    def login(request: LoginRequest, response: Response):
        require_not_throttled(request.username)
        try:
            # La contraseña descifra las claves privadas del usuario; si no descifra, no hay sesión
            client_session = ClientSession.open(home_of(request.username), request.passphrase,
                                                http_client=http_client)
        except IdentityError:
            throttle.record_failure(request.username)
            # Mismo mensaje si el usuario no existe o la contraseña falla: no se revela quién tiene cuenta
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "usuario o contraseña incorrectos")
        throttle.record_success(request.username)
        return start_session(response, request.username, client_session)

    @app.post("/api/logout", dependencies=[Depends(require_interface_request)])
    def logout(request: Request, response: Response):
        sessions.close(request.cookies.get(SESSION_COOKIE_NAME))
        response.delete_cookie(SESSION_COOKIE_NAME)
        return describe(None)

    # ---------- contactos ----------

    @app.get("/api/contacts")
    def list_contacts(user: LoggedInUser = Depends(require_user)):
        return [{"alias": alias, "display_name": identity.display_name,
                 "fingerprint": format_fingerprint_for_humans(identity.user_id)}
                for alias, identity in sorted(user.client_session.trust_store.aliases().items())]

    @app.post("/api/contacts")
    def trust_contact(request: TrustRequest, user: LoggedInUser = Depends(require_user)):
        session = user.client_session
        # Igual que `cryptostore trust`: se pide la identidad por su huella y se comprueba aquí
        identity = session.server_api.get_user(normalize_fingerprint(request.fingerprint))
        session.trust_store.pin(request.alias, identity, request.fingerprint)
        return list_contacts(user)

    @app.delete("/api/contacts/{alias}")
    def untrust_contact(alias: str, user: LoggedInUser = Depends(require_user)):
        user.client_session.trust_store.remove(alias)
        return list_contacts(user)

    # ---------- archivos ----------

    @app.get("/api/files")
    def list_files(user: LoggedInUser = Depends(require_user)):
        return [listing.to_json_dict() for listing in list_visible_files(user.client_session)]

    @app.post("/api/uploads")
    async def start_upload(request: Request, name: str, replace: str | None = None,
                           user: LoggedInUser = Depends(require_user)):
        safe_name = os.path.basename(name)
        if safe_name in ("", ".", ".."):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "nombre de archivo inválido")
        staging_directory = new_staging_directory()
        staged_path = os.path.join(staging_directory, safe_name)
        # El navegador entrega el archivo en claro a este proceso local; de aquí sale ya cifrado
        await _stream_body_to_file(request, staged_path, MAXIMUM_FILE_SIZE)

        def upload_work(report_progress: ProgressCallback) -> dict:
            try:
                result = FileUploader(user.client_session, on_progress=report_progress).upload(
                    staged_path, replace_file_id=replace or None)
            finally:
                shutil.rmtree(staging_directory, ignore_errors=True)
            return {"file_id": result.file_id, "content_version": result.content_version,
                    "total_blocks": result.total_blocks, "renewed_recipients": result.renewed_recipients,
                    "skipped_recipients": result.skipped_recipients}
        return jobs.start("upload", user.username, upload_work).to_json_dict()

    @app.post("/api/files/{file_id}/download")
    def start_download(file_id: FileId, request: PasswordConfirmation, user: LoggedInUser = Depends(require_user)):
        confirm_password(user, request.passphrase)
        staging_directory = new_staging_directory()

        def download_work(report_progress: ProgressCallback) -> dict:
            try:
                result = FileDownloader(user.client_session, on_progress=report_progress).download(
                    file_id, staging_directory)
            except BaseException:
                shutil.rmtree(staging_directory, ignore_errors=True)
                raise
            # La ruta local no se envía al navegador (claves con "_" se omiten); solo se usa para servirlo
            return {"name": os.path.basename(result.destination_path), "size": result.metadata.plaintext_size,
                    "content_version": result.content_version, "_local_path": result.destination_path}
        return jobs.start("download", user.username, download_work).to_json_dict()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, user: LoggedInUser = Depends(require_user)):
        return _require_job(jobs, job_id, user).to_json_dict()

    @app.get("/api/jobs/{job_id}/file")
    def take_downloaded_file(job_id: str, user: LoggedInUser = Depends(require_user)):
        job = _require_job(jobs, job_id, user)
        local_path = job.result.get("_local_path")
        if job.status != "done" or not local_path or not os.path.exists(local_path):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no hay archivo verificado para entregar")
        # Se entrega una vez y se borra la copia temporal en claro
        return FileResponse(local_path, filename=job.result["name"],
                            background=BackgroundTask(shutil.rmtree, os.path.dirname(local_path), True))

    @app.post("/api/files/{file_id}/share")
    def share_file(file_id: FileId, request: ShareRequest, user: LoggedInUser = Depends(require_user)):
        confirm_password(user, request.passphrase)
        return {"acl_epoch": AccessManager(user.client_session).share(file_id, request.alias)}

    @app.post("/api/files/{file_id}/revoke")
    def revoke_file(file_id: FileId, request: RevokeRequest, user: LoggedInUser = Depends(require_user)):
        confirm_password(user, request.passphrase)
        acl_epoch, recipient_label = AccessManager(user.client_session).revoke(file_id, request.recipient)
        return {"acl_epoch": acl_epoch, "message": revocation_scope_message(recipient_label)}

    @app.get("/api/files/{file_id}/recipients")
    def list_recipients(file_id: FileId, user: LoggedInUser = Depends(require_user)):
        acl_epoch, entries = AccessManager(user.client_session).recipients(file_id)
        return {"acl_epoch": acl_epoch,
                "recipients": [{"user_id": entry.user_id, "label": entry.label,
                                "fingerprint": format_fingerprint_for_humans(entry.user_id)} for entry in entries]}

    return app


def _require_job(jobs: JobRegistry, job_id: str, user: LoggedInUser):
    job = jobs.get(job_id, user.username)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tarea desconocida")
    return job


async def _stream_body_to_file(request: Request, path: str, maximum_bytes: int) -> None:
    received_bytes = 0
    with open(path, "wb") as staged_file:
        async for chunk in request.stream():
            received_bytes += len(chunk)
            # Se corta en cuanto supera el límite del enunciado (100 MiB)
            if received_bytes > maximum_bytes:
                staged_file.close()
                shutil.rmtree(os.path.dirname(path), ignore_errors=True)
                raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "el archivo supera el límite de 100 MiB")
            staged_file.write(chunk)


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(VerificationError)
    def rejected(_request: Request, error: VerificationError):
        return JSONResponse(status_code=422, content={"detail": f"RECHAZADO: {error}", "kind": "rejected"})

    @app.exception_handler(CryptoStoreError)
    def failed(_request: Request, error: CryptoStoreError):
        return JSONResponse(status_code=400, content={"detail": str(error), "kind": "error"})

    @app.exception_handler(ServerError)
    def server_failed(_request: Request, error: ServerError):
        return JSONResponse(status_code=502, content={"detail": str(error), "kind": "server"})

    @app.exception_handler(FileExistsError)
    def already_exists(_request: Request, error: FileExistsError):
        return JSONResponse(status_code=409, content={"detail": str(error), "kind": "error"})
