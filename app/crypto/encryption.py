# aes-256-gcm encryption for all credential fields stored in the database
# gcm mode gives us both encryption and an authentication tag, so any tampering is detected on decrypt

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_NONCE_LEN = 12


def encrypt_credential(key: bytes, plaintext: str) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    # a fresh random nonce every call means encrypting the same value twice gives different ciphertext
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    # prepend the nonce to the ciphertext so decrypt can find it, the nonce is not secret
    return nonce + ct


def decrypt_credential(key: bytes, ciphertext: bytes) -> str:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(ciphertext) < _NONCE_LEN + 16:
        raise InvalidTag("ciphertext too short")
    nonce, ct = ciphertext[:_NONCE_LEN], ciphertext[_NONCE_LEN:]
    # gcm will raise InvalidTag here if the key is wrong or the data was tampered with
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
