import secrets
import threading
import time


class SessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._data: dict[str, tuple[int, bytes, float]] = {}
        self._lock = threading.Lock()

    def create(self, *, user_id: int, key: bytes) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._data[sid] = (user_id, key, time.monotonic() + self._ttl)
        return sid

    def get(self, sid: str) -> tuple[int, bytes] | None:
        with self._lock:
            entry = self._data.get(sid)
            if entry is None:
                return None
            user_id, key, expires_at = entry
            if time.monotonic() >= expires_at:
                del self._data[sid]
                return None
            return user_id, key

    def delete(self, sid: str) -> None:
        with self._lock:
            self._data.pop(sid, None)
