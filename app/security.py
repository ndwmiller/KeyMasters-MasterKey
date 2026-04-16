import os
import re
import base64
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

ACCESS_TOKEN_EXPIRE_MINUTES = 30
ALGORITHM = "HS256"
_SESSION_SECRET = os.urandom(32).hex()  # valid for the lifetime of one app session

# Master Password (bcrypt)

def hash_master_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_master_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# AES-256-GCM Credential Encryption

def generate_encryption_salt() -> str:
    """Generate a random salt to store in the User record at account creation."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()

def get_encryption_key(master_password: str, salt: str) -> bytes:
    """Derive a raw 32-byte AES-256 key from the master password and the user's stored salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.urlsafe_b64decode(salt.encode()),
        iterations=260000,
    )
    return kdf.derive(master_password.encode())

def encrypt_data(data: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data.encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()

def decrypt_data(token: str, key: bytes) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        nonce, ciphertext = raw[:12], raw[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return None

# JWT Session Tokens

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload["exp"] = expire
    return jwt.encode(payload, _SESSION_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, _SESSION_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        return None

# Input Sanitization & Validation

def sanitize_text(value: str, max_length: int = 255) -> str:
    return value.strip()[:max_length]

def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))

def is_valid_url(url: str) -> bool:
    return bool(re.match(r'^https?://[^\s/$.?#][^\s]*$', url))

def is_valid_password(password: str, min_length: int = 12) -> bool:
    return len(password) >= min_length
