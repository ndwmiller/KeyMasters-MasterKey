# handles hashing and verifying the master password
# bcrypt is intentionally slow, which makes offline brute force attacks much more expensive
# the hash is what gets stored in the database, the plaintext password never touches disk

import bcrypt

# central spec for what counts as an acceptable master password.
# every flow that sets a master password — registration, change-password,
# forgot-password recovery — must run validate_master_password before
# hashing, so the rules cannot drift between entry points.
MIN_LEN = 12
MAX_LEN = 1024
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"


def validate_master_password(password: str) -> str | None:
    """Return None if the password meets every rule, else a human-readable
    reason. The reason is meant to be flashed back to the user."""
    if len(password) < MIN_LEN or len(password) > MAX_LEN:
        return f"must be between {MIN_LEN} and {MAX_LEN} characters"
    if not any(c.isupper() for c in password):
        return "must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "must contain at least one lowercase letter"
    if not any(c in _SYMBOLS for c in password):
        return "must contain at least one symbol"
    return None


def hash_master_password(password: str, cost: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(cost))


def verify_master_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        # bcrypt raises ValueError on malformed hashes rather than returning False
        return False
