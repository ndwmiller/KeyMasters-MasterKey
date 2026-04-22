from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError as _JoseError
from jose import jwt as _jose

JWTError = _JoseError
_DEFAULT_ALG = "HS256"
_DEFAULT_TTL = timedelta(minutes=15)


def issue_token(
    claims: dict[str, Any],
    secret: str,
    *,
    ttl: timedelta = _DEFAULT_TTL,
    algorithm: str = _DEFAULT_ALG,
) -> str:
    payload = dict(claims)
    payload["exp"] = datetime.now(timezone.utc) + ttl
    return _jose.encode(payload, secret, algorithm=algorithm)


def decode_token(
    token: str,
    secret: str,
    *,
    algorithm: str = _DEFAULT_ALG,
) -> dict[str, Any]:
    return _jose.decode(token, secret, algorithms=[algorithm])
