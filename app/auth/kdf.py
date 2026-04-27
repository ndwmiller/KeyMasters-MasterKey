# derives the aes-256 encryption key from the master password using pbkdf2
# the key is never stored anywhere, it is computed fresh every time the user logs in

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 600k iterations is the nist recommendation for pbkdf2-sha256 as of 2023
# it makes each guess slow enough to hurt brute force without making login feel laggy
_ITERATIONS = 600_000
_KEY_LEN = 32  # 32 bytes = 256 bits, which is what aes-256 needs
_SALT_LEN = 16


def new_salt() -> bytes:
    # each user gets a unique random salt so two users with the same password get different keys
    return os.urandom(_SALT_LEN)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))
