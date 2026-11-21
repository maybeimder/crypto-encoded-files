import json
import os
import secrets
import threading

from cryptostore.atomic_files import write_file_atomically
from cryptostore.primitives.symmetric import sha256
from cryptostore.protocol.serialization import canonical_json

TOKEN_BYTES = 32


# Tokens de sesión: solo dicen quién llama. No dan acceso al contenido, que sigue cifrado
class SessionTokens:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._user_id_by_token_hash: dict[str, str] = self._load()

    def issue(self, user_id: str) -> str:
        token = secrets.token_urlsafe(TOKEN_BYTES)
        with self._lock:
            # En disco va la huella del token, no el token: una copia del archivo no sirve para suplantar
            self._user_id_by_token_hash[self._hash(token)] = user_id
            write_file_atomically(self._path, canonical_json(self._user_id_by_token_hash))
        return token

    def user_for(self, token: str) -> str | None:
        return self._user_id_by_token_hash.get(self._hash(token))

    @staticmethod
    def _hash(token: str) -> str:
        return sha256(token.encode("utf-8")).hex()

    def _load(self) -> dict[str, str]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "rb") as tokens_file:
            return json.loads(tokens_file.read())
