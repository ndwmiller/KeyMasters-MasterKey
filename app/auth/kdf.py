# derives the aes-256 key encryption keys (KEKs) used to wrap/unwrap the
# per-user Master Encryption Key (MEK). The MEK itself is what encrypts every
# credential field; the KEK is just the derived key that wraps the MEK.
#
# We derive two distinct KEKs per user:
#   - master KEK   = PBKDF2(master_password, kdf_salt)
#   - recovery KEK = PBKDF2(normalized_security_answers, recovery_salt)
# Both wrap the same MEK, so a successful unwrap with either KEK yields the
# same MEK and the same access to credentials.

import os
import unicodedata

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


def normalize_answer(answer: str) -> str:
    # Recovery answers are typically low-entropy human inputs. Normalizing
    # whitespace, case, and unicode form lets users type "  Fluffy " on
    # registration and "fluffy" on recovery and still match.
    return unicodedata.normalize("NFKC", answer).strip().casefold()


def derive_recovery_key(answer1: str, answer2: str, salt: bytes) -> bytes:
    # Joining with a NUL byte that cannot appear in casefolded text guarantees
    # ("ab", "cd") and ("a", "bcd") derive different keys.
    material = f"{normalize_answer(answer1)}\x00{normalize_answer(answer2)}"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(material.encode("utf-8"))
