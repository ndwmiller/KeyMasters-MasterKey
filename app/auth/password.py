# handles hashing and verifying the master password
# bcrypt is intentionally slow, which makes offline brute force attacks much more expensive
# the hash is what gets stored in the database, the plaintext password never touches disk

import bcrypt


def hash_master_password(password: str, cost: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(cost))


def verify_master_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        # bcrypt raises ValueError on malformed hashes rather than returning False
        return False
