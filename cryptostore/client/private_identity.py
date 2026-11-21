import json
import os
from dataclasses import dataclass
from functools import cached_property

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from cryptostore.atomic_files import write_file_atomically
from cryptostore.errors import FormatError, IdentityError, VerificationError
from cryptostore.primitives.public_key import (
    PRIVATE_KEY_SIZE,
    encryption_public_key_from_private,
    generate_encryption_keypair,
    generate_signing_keypair,
    signing_public_key_from_private,
)
from cryptostore.primitives.symmetric import (
    AEAD_NONCE_SIZE,
    SYMMETRIC_KEY_SIZE,
    AuthenticatedCipher,
    random_bytes,
)
from cryptostore.protocol.public_identity import PublicIdentity
from cryptostore.protocol.serialization import canonical_json, from_base64, require_field, to_base64

IDENTITY_FILE_FORMAT = "p5-identity/1"
SCRYPT_SALT_SIZE = 16


# Costo de scrypt; con los valores por defecto cada intento de contraseña usa ~32 MiB
@dataclass(frozen=True)
class ScryptParameters:
    cost: int = 2**15
    block_size: int = 8
    parallelism: int = 1

    def __post_init__(self):
        cost_is_power_of_two = self.cost > 1 and self.cost & (self.cost - 1) == 0
        if not (cost_is_power_of_two and 2**14 <= self.cost <= 2**20 and 1 <= self.block_size <= 32
                and 1 <= self.parallelism <= 16):
            raise FormatError("parámetros de scrypt fuera de rango")

    def derive_key(self, passphrase: str, salt: bytes) -> bytes:
        # scrypt es lento y gasta memoria a propósito: probar contraseñas por fuerza bruta sale caro
        key_derivation = Scrypt(
            salt=salt, length=SYMMETRIC_KEY_SIZE, n=self.cost, r=self.block_size, p=self.parallelism
        )
        return key_derivation.derive(passphrase.encode("utf-8"))

    def to_json_dict(self) -> dict:
        return {"name": "scrypt", "cost": self.cost, "block_size": self.block_size, "parallelism": self.parallelism}

    @classmethod
    def from_json_dict(cls, data: dict) -> "ScryptParameters":
        if require_field(data, "name", str) != "scrypt":
            raise FormatError("función de derivación de contraseña no soportada")
        return cls(
            require_field(data, "cost", int),
            require_field(data, "block_size", int),
            require_field(data, "parallelism", int),
        )


@dataclass(frozen=True)
class PrivateIdentity:
    display_name: str
    encryption_private_key: bytes  # X25519: abre envolventes
    signing_private_key: bytes     # Ed25519: firma manifiestos

    @classmethod
    def generate(cls, display_name: str) -> "PrivateIdentity":
        return cls(
            display_name=display_name,
            encryption_private_key=generate_encryption_keypair().private_key,
            signing_private_key=generate_signing_keypair().private_key,
        )

    @cached_property
    def public(self) -> PublicIdentity:
        return PublicIdentity(
            display_name=self.display_name,
            encryption_public_key=encryption_public_key_from_private(self.encryption_private_key),
            signing_public_key=signing_public_key_from_private(self.signing_private_key),
        )

    @property
    def user_id(self) -> str:
        return self.public.user_id

    def save(self, path: str, passphrase: str, *, scrypt_parameters: ScryptParameters = ScryptParameters(),
             overwrite: bool = False) -> None:
        if not passphrase:
            raise IdentityError("la contraseña no puede estar vacía")
        if os.path.exists(path) and not overwrite:
            raise IdentityError(f"ya existe una identidad en {path}")

        # La clave que cifra el archivo no se guarda: se recalcula desde la contraseña y una sal aleatoria
        salt = random_bytes(SCRYPT_SALT_SIZE)
        file_key = scrypt_parameters.derive_key(passphrase, salt)
        header = {
            "format": IDENTITY_FILE_FORMAT,
            "display_name": self.display_name,
            "key_derivation": scrypt_parameters.to_json_dict(),
            "salt": to_base64(salt),
        }
        nonce = random_bytes(AEAD_NONCE_SIZE)
        private_keys = self.encryption_private_key + self.signing_private_key
        # La cabecera va como datos asociados: editar el nombre o bajar el costo de scrypt rompe el archivo
        encrypted_keys = AuthenticatedCipher(file_key).encrypt(nonce, private_keys, canonical_json(header))

        file_content = {"header": header, "encrypted_private_keys": to_base64(nonce + encrypted_keys)}
        # Legible solo por el usuario dueño del archivo
        write_file_atomically(path, canonical_json(file_content), permissions=0o600)

    @classmethod
    def load(cls, path: str, passphrase: str) -> "PrivateIdentity":
        try:
            with open(path, "rb") as identity_file:
                file_content = json.loads(identity_file.read())
            header = require_field(file_content, "header", dict)
            if require_field(header, "format", str) != IDENTITY_FILE_FORMAT:
                raise FormatError("formato de identidad no soportado")
            scrypt_parameters = ScryptParameters.from_json_dict(require_field(header, "key_derivation", dict))
            salt = from_base64(require_field(header, "salt", str), SCRYPT_SALT_SIZE)
            nonce_and_encrypted_keys = from_base64(require_field(file_content, "encrypted_private_keys", str))

            # Misma contraseña + misma sal = misma clave; cualquier otra contraseña no descifra
            file_key = scrypt_parameters.derive_key(passphrase, salt)
            nonce = nonce_and_encrypted_keys[:AEAD_NONCE_SIZE]
            encrypted_keys = nonce_and_encrypted_keys[AEAD_NONCE_SIZE:]
            private_keys = AuthenticatedCipher(file_key).decrypt(nonce, encrypted_keys, canonical_json(header))
        except VerificationError as error:
            raise IdentityError("contraseña incorrecta o archivo de identidad alterado") from error
        except (OSError, ValueError, FormatError) as error:
            raise IdentityError(f"no se pudo leer la identidad: {error}") from error

        return cls(
            display_name=require_field(header, "display_name", str),
            encryption_private_key=private_keys[:PRIVATE_KEY_SIZE],
            signing_private_key=private_keys[PRIVATE_KEY_SIZE:],
        )
