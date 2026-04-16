import base64

from cryptography.fernet import Fernet


def _fernet(key: bytes) -> Fernet:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_credential(key: bytes, plaintext: str) -> bytes:
    return _fernet(key).encrypt(plaintext.encode("utf-8"))


def decrypt_credential(key: bytes, ciphertext: bytes) -> str:
    return _fernet(key).decrypt(ciphertext).decode("utf-8")
