# aes-256-gcm encryption for all credential fields stored in the database
# gcm mode gives us both encryption and an authentication tag, so any tampering is detected on decrypt

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_NONCE_LEN = 12
_KEY_LEN = 32  # AES-256


def new_mek() -> bytes:
    # The Master Encryption Key is generated once per user at registration and
    # never changes for the life of the account. Changing the master password
    # only re-wraps this key under a fresh KEK; it does not rotate the MEK,
    # which would force re-encrypting every credential.
    return os.urandom(_KEY_LEN)


def encrypt_credential(key: bytes, plaintext: str) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError("key must be 32 bytes")
    # a fresh random nonce every call means encrypting the same value twice gives different ciphertext
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    # prepend the nonce to the ciphertext so decrypt can find it, the nonce is not secret
    return nonce + ct


def decrypt_credential(key: bytes, ciphertext: bytes) -> str:
    if len(key) != _KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(ciphertext) < _NONCE_LEN + 16:
        raise InvalidTag("ciphertext too short")
    nonce, ct = ciphertext[:_NONCE_LEN], ciphertext[_NONCE_LEN:]
    # gcm will raise InvalidTag here if the key is wrong or the data was tampered with
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def wrap_key(kek: bytes, mek: bytes) -> bytes:
    # AES-GCM-wrapped key = nonce || ciphertext+tag. The wrapped value is
    # ciphertext-only; an attacker who steals it must brute-force the
    # password-derived KEK to recover the MEK.
    if len(kek) != _KEY_LEN:
        raise ValueError("kek must be 32 bytes")
    if len(mek) != _KEY_LEN:
        raise ValueError("mek must be 32 bytes")
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(kek).encrypt(nonce, mek, None)
    return nonce + ct


def unwrap_key(kek: bytes, wrapped: bytes) -> bytes:
    # Returns the 32-byte MEK or raises InvalidTag if the KEK is wrong.
    if len(kek) != _KEY_LEN:
        raise ValueError("kek must be 32 bytes")
    if len(wrapped) < _NONCE_LEN + 16:
        raise InvalidTag("wrapped key too short")
    nonce, ct = wrapped[:_NONCE_LEN], wrapped[_NONCE_LEN:]
    return AESGCM(kek).decrypt(nonce, ct, None)
