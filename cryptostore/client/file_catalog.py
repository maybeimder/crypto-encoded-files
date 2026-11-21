from dataclasses import dataclass

from cryptostore.client.file_version_resolver import FileVersionResolver
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.errors import CryptoStoreError, IdentityError

PROBLEM_INCOMPLETE = "incomplete"
PROBLEM_UNVERIFIED_OWNER = "unverified_owner"
PROBLEM_OTHER = "other"


@dataclass(frozen=True)
class FileListing:
    file_id: str
    latest_version: int
    role: str
    owner_id: str
    owner_label: str
    owner_claimed_name: str  # nombre que dice el servidor: sirve de pista, no prueba nada
    name: str | None
    plaintext_size: int | None
    problem_kind: str | None
    problem: str | None

    def to_json_dict(self) -> dict:
        return dict(self.__dict__)


def list_visible_files(session: ClientSession) -> list[FileListing]:
    resolver = FileVersionResolver(session)
    listings = []
    for listed_file in session.server_api.list_files():
        owner_id = listed_file["owner_id"]
        owner_claimed_name = _claimed_name(session, owner_id)
        name, plaintext_size, problem_kind, problem = None, None, None, None
        if listed_file["latest_version"] == 0:
            problem_kind, problem = PROBLEM_INCOMPLETE, "carga sin terminar"
        else:
            try:
                # El nombre real solo aparece si se verifica al dueño y se abre la envolvente propia
                metadata = resolver.resolve(listed_file["file_id"]).metadata
                name, plaintext_size = metadata.name, metadata.plaintext_size
            except IdentityError:
                # No es un fallo: falta verificar la huella de quien lo comparte antes de confiar en su firma
                problem_kind = PROBLEM_UNVERIFIED_OWNER
                problem = f"compartido por {owner_claimed_name}, a quien aún no verificaste"
            except (CryptoStoreError, ServerError) as error:
                problem_kind, problem = PROBLEM_OTHER, f"no verificable: {error}"
        listings.append(FileListing(listed_file["file_id"], listed_file["latest_version"], listed_file["role"],
                                    owner_id, _owner_label(session, owner_id, owner_claimed_name), owner_claimed_name,
                                    name, plaintext_size, problem_kind, problem))
    return listings


def _owner_label(session: ClientSession, owner_id: str, owner_claimed_name: str) -> str:
    if owner_id == session.identity.user_id:
        return "tú"
    # Alias de la libreta si está verificado; si no, el nombre que dice el servidor, marcado como tal
    return session.trust_store.alias_of(owner_id) or f"{owner_claimed_name} (sin verificar)"


def _claimed_name(session: ClientSession, user_id: str) -> str:
    if user_id == session.identity.user_id:
        return session.identity.display_name
    try:
        return session.server_api.get_user(user_id).display_name
    except (CryptoStoreError, ServerError):
        return user_id[:12]
