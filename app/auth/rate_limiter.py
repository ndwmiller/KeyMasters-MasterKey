import threading
import time


class LoginRateLimiter:
    # sliding window limiter keyed by username.
    # failed attempts older than the window are discarded on each check.

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_blocked(self, username: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._attempts.get(username, []) if now - t < self._window]
            self._attempts[username] = recent
            return len(recent) >= self._max

    def record_failure(self, username: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._attempts.setdefault(username, []).append(now)

    def clear(self, username: str) -> None:
        with self._lock:
            self._attempts.pop(username, None)
