import time

import httpx

from cryptostore.protocol.access_grant import AccessGrant
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.public_identity import PublicIdentity

_RETRYABLE_STATUS_CODES = {502, 503, 504}


class ServerError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(f"el servidor respondió {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


# Traduce cada operación a su petición HTTP. No descifra ni verifica nada: eso lo hace quien la usa
class ServerApi:
    def __init__(self, http_client: httpx.Client, token: str | None = None,
                 maximum_attempts: int = 3, retry_delay_seconds: float = 0.5):
        self._http_client = http_client
        self._token = token
        self._maximum_attempts = maximum_attempts
        self._retry_delay_seconds = retry_delay_seconds

    @classmethod
    def connect(cls, server_url: str, token: str | None = None) -> "ServerApi":
        return cls(httpx.Client(base_url=server_url, timeout=60.0), token)

    def register(self, identity: PublicIdentity) -> tuple[str, str]:
        # Registrar no se reintenta: un segundo intento chocaría con el primero (409)
        response = self._request("POST", "/users", json=identity.to_json_dict(),
                                 expected_status=201, retry=False, authenticated=False)
        content = response.json()
        self._token = content["token"]
        return content["user_id"], content["token"]

    def list_users(self) -> list[dict]:
        return self._request("GET", "/users").json()

    def get_user(self, user_id: str) -> PublicIdentity:
        return PublicIdentity.from_json_dict(self._request("GET", f"/users/{user_id}").json())

    def list_files(self) -> list[dict]:
        return self._request("GET", "/files").json()

    def put_block(self, file_id: str, version: int, index: int, payload: bytes) -> None:
        self._request("PUT", f"/files/{file_id}/versions/{version}/blocks/{index}", content=payload,
                      headers={"Content-Type": "application/octet-stream"}, expected_status=204)

    def list_uploaded_blocks(self, file_id: str, version: int) -> dict[int, str]:
        try:
            listed = self._request("GET", f"/files/{file_id}/versions/{version}/blocks").json()
        except ServerError as error:
            # Archivo aún inexistente en el servidor: no hay nada subido
            if error.status_code == 404:
                return {}
            raise
        return {int(index): block_hash for index, block_hash in listed.items()}

    def get_block(self, file_id: str, version: int, index: int) -> bytes:
        return self._request("GET", f"/files/{file_id}/versions/{version}/blocks/{index}").content

    def commit_manifest(self, manifest: SignedManifest) -> None:
        body = manifest.body
        self._request("PUT", f"/files/{body.file_id.hex()}/versions/{body.content_version}/manifest",
                      json=manifest.to_json_dict(), expected_status=204)

    def get_manifest(self, file_id: str, version: int | None = None) -> SignedManifest:
        url = f"/files/{file_id}/manifest" if version is None else f"/files/{file_id}/versions/{version}/manifest"
        return SignedManifest.from_json_dict(self._request("GET", url).json())

    def put_grant(self, grant: AccessGrant) -> int:
        url = f"/files/{grant.file_id.hex()}/grants/{grant.recipient_id}"
        return self._request("PUT", url, json=grant.to_json_dict()).json()["acl_epoch"]

    def delete_grant(self, file_id: str, recipient_id: str) -> int:
        return self._request("DELETE", f"/files/{file_id}/grants/{recipient_id}").json()["acl_epoch"]

    def get_my_grant(self, file_id: str) -> AccessGrant:
        return AccessGrant.from_json_dict(self._request("GET", f"/files/{file_id}/grants/mine").json())

    def list_grants(self, file_id: str) -> tuple[int, list[str]]:
        content = self._request("GET", f"/files/{file_id}/grants").json()
        return content["acl_epoch"], content["recipient_ids"]

    def _request(self, method: str, url: str, *, expected_status: int = 200, retry: bool = True,
                 authenticated: bool = True, headers: dict | None = None, **request_options) -> httpx.Response:
        headers = dict(headers or {})
        if authenticated and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        attempts_allowed = self._maximum_attempts if retry else 1

        for attempt_number in range(1, attempts_allowed + 1):
            try:
                response = self._http_client.request(method, url, headers=headers, **request_options)
            except httpx.TransportError as error:
                # Red caída o conexión cortada: se reintenta con espera creciente
                if attempt_number == attempts_allowed:
                    raise ServerError(0, f"no se pudo contactar al servidor ({error})") from error
                time.sleep(self._retry_delay_seconds * attempt_number)
                continue
            # Servidor momentáneamente no disponible: también se reintenta
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt_number < attempts_allowed:
                time.sleep(self._retry_delay_seconds * attempt_number)
                continue
            if response.status_code != expected_status:
                raise ServerError(response.status_code, _error_detail(response))
            return response
        raise AssertionError("inalcanzable")


def _error_detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail", response.text)
    except ValueError:
        detail = response.text
    return detail if isinstance(detail, str) else str(detail)
