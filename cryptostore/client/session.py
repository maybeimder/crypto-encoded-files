import os
from dataclasses import dataclass

import httpx

from cryptostore.client.private_identity import PrivateIdentity
from cryptostore.client.server_api import ServerApi
from cryptostore.client.trust_store import TrustStore
from cryptostore.client.workspace import ClientWorkspace, SessionInfo
from cryptostore.errors import IdentityError
from cryptostore.protocol.public_identity import PublicIdentity


@dataclass
class ClientSession:
    workspace: ClientWorkspace
    identity: PrivateIdentity
    trust_store: TrustStore
    server_api: ServerApi

    @classmethod
    def create(cls, home_directory: str, display_name: str, passphrase: str, server_url: str,
               http_client: httpx.Client | None = None) -> "ClientSession":
        workspace = ClientWorkspace(home_directory)
        if workspace.is_initialized():
            raise IdentityError(f"ya existe una identidad en {workspace.home_directory}")
        identity = PrivateIdentity.generate(display_name)
        server_api = _build_server_api(server_url, None, http_client)
        # Se registra antes de guardar nada: si el servidor falla no queda una identidad huérfana
        user_id, token = server_api.register(identity.public)
        os.makedirs(workspace.home_directory, mode=0o700, exist_ok=True)
        identity.save(workspace.identity_path, passphrase)
        workspace.save_session(SessionInfo(server_url, user_id, token))
        return cls(workspace, identity, TrustStore(workspace.trust_store_path), server_api)

    @classmethod
    def open(cls, home_directory: str, passphrase: str, http_client: httpx.Client | None = None) -> "ClientSession":
        workspace = ClientWorkspace(home_directory)
        if not workspace.is_initialized():
            raise IdentityError(f"no hay identidad en {workspace.home_directory}: ejecute primero 'init'")
        identity = PrivateIdentity.load(workspace.identity_path, passphrase)
        session_info = workspace.load_session()
        server_api = _build_server_api(session_info.server_url, session_info.token, http_client)
        return cls(workspace, identity, TrustStore(workspace.trust_store_path), server_api)

    def trusted_identity(self, user_id: str) -> PublicIdentity:
        # Uno mismo siempre es de confianza; cualquier otro debe estar fijado en la libreta local.
        # Nunca se usa la clave pública que diga el servidor
        if user_id == self.identity.user_id:
            return self.identity.public
        return self.trust_store.require_trusted(user_id)

    def describe_user(self, user_id: str) -> str:
        if user_id == self.identity.user_id:
            return "tú"
        return self.trust_store.alias_of(user_id) or f"{user_id[:12]}… (sin verificar)"


def _build_server_api(server_url: str, token: str | None, http_client: httpx.Client | None) -> ServerApi:
    # Las pruebas inyectan su propio cliente HTTP; en uso normal se conecta a la URL
    if http_client is not None:
        return ServerApi(http_client, token)
    return ServerApi.connect(server_url, token)
