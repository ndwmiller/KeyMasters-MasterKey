# fastapi dependency functions shared across the api routes
# they pull shared objects out of app.state so individual routes don't have to know where they live

from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, Request

from app.auth.jwt import JWTError, decode_token
from app.auth.rate_limiter import LoginRateLimiter
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import AuthError


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.sessions


def get_rate_limiter(request: Request) -> LoginRateLimiter:
    return request.app.state.rate_limiter


@dataclass
class CurrentSession:
    user_id: int
    key: bytes


def _extract_token(authorization: str, cookie_token: str | None) -> str:
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1]
    if cookie_token:
        return cookie_token
    raise AuthError()


def get_current_session(
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
    sessions: SessionStore = Depends(get_session_store),
) -> CurrentSession:
    token = _extract_token(authorization, mk_session)
    try:
        claims = decode_token(token, get_settings().jwt_secret)
    except JWTError:
        raise AuthError()
    sid = claims.get("sid")
    if not sid:
        raise AuthError()
    entry = sessions.get(sid)
    if entry is None:
        raise AuthError()
    user_id, key = entry
    return CurrentSession(user_id=user_id, key=key)
