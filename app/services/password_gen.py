import secrets
import string

_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"
_ALPHABET = string.ascii_letters + string.digits + _SYMBOLS


def generate_password(length: int = 20) -> str:
    if length < 8:
        raise ValueError("length must be >= 8")
    while True:
        pw = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in _SYMBOLS for c in pw)
        ):
            return pw
