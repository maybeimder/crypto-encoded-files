import json
import os

from cryptostore.atomic_files import write_file_atomically
from cryptostore.errors import FormatError, IdentityError
from cryptostore.protocol.public_identity import PublicIdentity, normalize_fingerprint
from cryptostore.protocol.serialization import canonical_json

TRUST_STORE_FORMAT = "p5-trust-store/1"


# Libreta local de contactos verificados (TOFU: se confía en la clave vista y confirmada la primera vez)
class TrustStore:
    def __init__(self, path: str):
        self._path = path
        self._load()

    # Se relee el disco en cada consulta: la terminal y la web pueden modificar la misma libreta
    @property
    def _identities_by_alias(self) -> dict[str, PublicIdentity]:
        return self._load()

    def pin(self, alias: str, identity: PublicIdentity, fingerprint_confirmed_out_of_band: str) -> None:
        # La huella dictada por el contacto (en persona, por llamada) debe coincidir con las claves recibidas
        if normalize_fingerprint(fingerprint_confirmed_out_of_band) != identity.user_id:
            raise IdentityError("la huella no coincide con la clave pública recibida: posible suplantación")

        identities_by_alias = self._identities_by_alias
        already_pinned = identities_by_alias.get(alias)
        if already_pinned is not None:
            # Un alias conocido que llega con otra clave es justo el ataque que TOFU detecta
            if already_pinned.user_id != identity.user_id:
                raise IdentityError(
                    f"'{alias}' ya está fijado a otra clave. Si el contacto cambió de clave, elimínelo primero"
                )
            return
        if self.find_by_user_id(identity.user_id) is not None:
            raise IdentityError("esa identidad ya está fijada con otro alias")

        identities_by_alias[alias] = identity
        self._save(identities_by_alias)

    def remove(self, alias: str) -> None:
        identities_by_alias = self._identities_by_alias
        if identities_by_alias.pop(alias, None) is None:
            raise IdentityError(f"'{alias}' no está en la libreta")
        self._save(identities_by_alias)

    def find_by_alias(self, alias: str) -> PublicIdentity | None:
        return self._identities_by_alias.get(alias)

    def find_by_user_id(self, user_id: str) -> PublicIdentity | None:
        return next(
            (identity for identity in self._identities_by_alias.values() if identity.user_id == user_id), None
        )

    def alias_of(self, user_id: str) -> str | None:
        return next((alias for alias, identity in self._identities_by_alias.items() if identity.user_id == user_id),
                    None)

    def require_trusted(self, user_id: str) -> PublicIdentity:
        identity = self.find_by_user_id(user_id)
        if identity is None:
            raise IdentityError("la identidad no está verificada en la libreta local")
        return identity

    def require_alias(self, alias: str) -> PublicIdentity:
        identity = self.find_by_alias(alias)
        if identity is None:
            raise IdentityError(f"'{alias}' no está en la libreta: verifique antes su huella")
        return identity

    def aliases(self) -> dict[str, PublicIdentity]:
        return dict(self._identities_by_alias)

    def _load(self) -> dict[str, PublicIdentity]:
        if not os.path.exists(self._path):
            return {}
        try:
            with open(self._path, "rb") as trust_file:
                content = json.loads(trust_file.read())
            if content.get("format") != TRUST_STORE_FORMAT:
                raise IdentityError("formato de libreta no soportado")
            return {
                alias: PublicIdentity.from_json_dict(identity_data)
                for alias, identity_data in content["contacts"].items()
            }
        except (OSError, ValueError, KeyError, AttributeError, FormatError) as error:
            raise IdentityError(f"no se pudo leer la libreta de confianza: {error}") from error

    def _save(self, identities_by_alias: dict[str, PublicIdentity]) -> None:
        content = {
            "format": TRUST_STORE_FORMAT,
            "contacts": {alias: identity.to_json_dict() for alias, identity in identities_by_alias.items()},
        }
        write_file_atomically(self._path, canonical_json(content), permissions=0o600)
