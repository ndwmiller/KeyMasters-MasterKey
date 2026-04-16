from dataclasses import dataclass

from fastapi import Depends, Header, Request

from app.auth.jwt import JWTError, decode_token
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import AuthError


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.sessions


@dataclass
class CurrentSession:
    user_id: int
    key: bytes


def get_current_session(
    authorization: str = Header(default=""),
    sessions: SessionStore = Depends(get_session_store),
) -> CurrentSession:
    if not authorization.lower().startswith("bearer "):
        raise AuthError()
    token = authorization.split(" ", 1)[1]
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
