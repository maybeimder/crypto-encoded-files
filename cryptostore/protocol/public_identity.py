import re
from dataclasses import dataclass

from cryptostore.errors import FormatError
from cryptostore.primitives.public_key import PUBLIC_KEY_SIZE
from cryptostore.primitives.symmetric import sha256
from cryptostore.protocol.serialization import from_base64, require_field, to_base64

FINGERPRINT_HEX_LENGTH = 64
MAX_DISPLAY_NAME_LENGTH = 64
_FINGERPRINT_SEPARATORS = re.compile(r"[\s:\-]")


def compute_fingerprint(encryption_public_key: bytes, signing_public_key: bytes) -> str:
    # Cubre ambas claves públicas: cambiar cualquiera de las dos cambia la huella
    return sha256(encryption_public_key + signing_public_key).hex()


def normalize_fingerprint(typed_fingerprint: str) -> str:
    # Acepta la huella como la escribe una persona: espacios, dos puntos, guiones, mayúsculas
    return _FINGERPRINT_SEPARATORS.sub("", typed_fingerprint).lower()


def format_fingerprint_for_humans(fingerprint: str) -> str:
    # Grupos de 4 caracteres para dictarla y compararla en voz alta
    return " ".join(fingerprint[position:position + 4] for position in range(0, len(fingerprint), 4))


@dataclass(frozen=True)
class PublicIdentity:
    display_name: str
    encryption_public_key: bytes
    signing_public_key: bytes

    @property
    def user_id(self) -> str:
        # Sin autoridad central: el identificador de un usuario es la huella de sus claves
        return compute_fingerprint(self.encryption_public_key, self.signing_public_key)

    def to_json_dict(self) -> dict:
        return {
            "display_name": self.display_name,
            "encryption_public_key": to_base64(self.encryption_public_key),
            "signing_public_key": to_base64(self.signing_public_key),
        }

    @classmethod
    def from_json_dict(cls, data: dict) -> "PublicIdentity":
        display_name = require_field(data, "display_name", str)
        if not 0 < len(display_name) <= MAX_DISPLAY_NAME_LENGTH:
            raise FormatError("nombre visible vacío o demasiado largo")
        return cls(
            display_name=display_name,
            encryption_public_key=from_base64(require_field(data, "encryption_public_key", str), PUBLIC_KEY_SIZE),
            signing_public_key=from_base64(require_field(data, "signing_public_key", str), PUBLIC_KEY_SIZE),
        )
