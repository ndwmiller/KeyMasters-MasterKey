import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_rate_limiter, get_session_store
from app.auth.jwt import JWTError, decode_token, issue_token
from app.auth.kdf import derive_key, new_salt
from app.auth.password import hash_master_password, verify_master_password
from app.auth.rate_limiter import LoginRateLimiter
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.db import repository as repo
from app.errors import AuthError
from app.schemas.user import LoginRequest, RegisterRequest, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> UserOut:
    settings = get_settings()
    try:
        uid = repo.create_user(
            settings.db_path,
            username=body.username,
            bcrypt_hash=hash_master_password(body.master_password, cost=settings.bcrypt_cost),
            kdf_salt=new_salt(),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="username already taken")
    return UserOut(id=uid, username=body.username)


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    sessions: SessionStore = Depends(get_session_store),
    limiter: LoginRateLimiter = Depends(get_rate_limiter),
) -> LoginResponse:
    settings = get_settings()
    if limiter.is_blocked(body.username):
        raise HTTPException(status_code=429, detail="too many failed attempts, try again later")
    user = repo.get_user_by_username(settings.db_path, body.username)
    if user is None or not verify_master_password(body.master_password, user["bcrypt_hash"]):
        limiter.record_failure(body.username)
        raise AuthError()
    limiter.clear(body.username)
    key = derive_key(body.master_password, user["kdf_salt"])
    sid = sessions.create(user_id=user["id"], key=key)
    token = issue_token(
        {"sub": str(user["id"]), "sid": sid},
        settings.jwt_secret,
        ttl=timedelta(minutes=settings.jwt_ttl_minutes),
        algorithm=settings.jwt_algorithm,
    )
    return LoginResponse(access_token=token)


@router.post("/logout", status_code=204)
def logout(
    authorization: str = Header(default=""),
    sessions: SessionStore = Depends(get_session_store),
) -> None:
    if not authorization.lower().startswith("bearer "):
        raise AuthError()
    token = authorization.split(" ", 1)[1]
    try:
        claims = decode_token(token, get_settings().jwt_secret)
    except JWTError:
        raise AuthError()
    sid = claims.get("sid", "")
    sessions.delete(sid)
