import secrets
import threading
import time
from dataclasses import dataclass, field

from cryptostore.client.session import ClientSession


@dataclass
class LoggedInUser:
    username: str
    client_session: ClientSession
    session_ids: set[str] = field(default_factory=set)


# Sesiones del navegador. Las claves privadas de un usuario viven en memoria solo mientras tenga alguna abierta
class WebSessionRegistry:
    def __init__(self, idle_seconds: float):
        self._idle_seconds = idle_seconds
        self._lock = threading.Lock()
        self._users_by_name: dict[str, LoggedInUser] = {}
        self._username_by_session: dict[str, str] = {}
        self._last_seen_by_session: dict[str, float] = {}

    def open(self, username: str, client_session: ClientSession) -> str:
        # Identificador imposible de adivinar; viaja solo en una cookie HttpOnly
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            # Dos pestañas del mismo usuario comparten las claves ya abiertas
            user = self._users_by_name.setdefault(username, LoggedInUser(username, client_session))
            user.session_ids.add(session_id)
            self._username_by_session[session_id] = username
            self._last_seen_by_session[session_id] = time.monotonic()
        return session_id

    def find(self, session_id: str | None) -> LoggedInUser | None:
        if not session_id:
            return None
        with self._lock:
            username = self._username_by_session.get(session_id)
            if username is None:
                return None
            # Inactiva demasiado tiempo: se cierra como si el usuario hubiera salido
            if time.monotonic() - self._last_seen_by_session[session_id] > self._idle_seconds:
                self._close_locked(session_id)
                return None
            self._last_seen_by_session[session_id] = time.monotonic()
            return self._users_by_name[username]

    def close(self, session_id: str | None) -> None:
        with self._lock:
            if session_id in self._username_by_session:
                self._close_locked(session_id)

    def _close_locked(self, session_id: str) -> None:
        username = self._username_by_session.pop(session_id)
        self._last_seen_by_session.pop(session_id, None)
        user = self._users_by_name[username]
        user.session_ids.discard(session_id)
        # Sin sesiones abiertas, las claves privadas salen de memoria
        if not user.session_ids:
            del self._users_by_name[username]


class LoginThrottle:
    def __init__(self, maximum_failures: int, lock_seconds: float):
        self._maximum_failures = maximum_failures
        self._lock_seconds = lock_seconds
        self._lock = threading.Lock()
        self._failures_by_username: dict[str, int] = {}
        self._locked_until_by_username: dict[str, float] = {}

    def seconds_locked(self, username: str) -> float:
        with self._lock:
            return max(0.0, self._locked_until_by_username.get(username, 0.0) - time.monotonic())

    def record_failure(self, username: str) -> None:
        with self._lock:
            failures = self._failures_by_username.get(username, 0) + 1
            # Tras varios fallos seguidos se bloquea un rato: adivinar contraseñas se vuelve lentísimo
            if failures >= self._maximum_failures:
                self._locked_until_by_username[username] = time.monotonic() + self._lock_seconds
                failures = 0
            self._failures_by_username[username] = failures

    def record_success(self, username: str) -> None:
        with self._lock:
            self._failures_by_username.pop(username, None)
