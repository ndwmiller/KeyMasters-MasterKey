# json api endpoints for registration, login, and logout
# these are used by api clients, the browser-facing html versions live in app/web/auth.py

import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_rate_limiter, get_session_store
from app.auth.jwt import JWTError, decode_token, issue_token
from app.auth.kdf import derive_key, derive_recovery_key, new_salt
from app.auth.password import hash_master_password, verify_master_password
from app.auth.rate_limiter import LoginRateLimiter
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.crypto.encryption import new_mek, unwrap_key, wrap_key
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
    # Build the wrapped-MEK pair: one for the master password, one for the
    # security-question recovery flow. Both wrap the same MEK, so either
    # successful unwrap grants the same access to credentials.
    mek = new_mek()
    mp_salt = new_salt()
    rec_salt = new_salt()
    master_kek = derive_key(body.master_password, mp_salt)
    recovery_kek = derive_recovery_key(body.recovery_a1, body.recovery_a2, rec_salt)
    try:
        uid = repo.create_user(
            settings.db_path,
            username=body.username,
            bcrypt_hash=hash_master_password(body.master_password, cost=settings.bcrypt_cost),
            kdf_salt=mp_salt,
            master_wrapped_mek=wrap_key(master_kek, mek),
            recovery_salt=rec_salt,
            recovery_q1=body.recovery_q1,
            recovery_q2=body.recovery_q2,
            recovery_wrapped_mek=wrap_key(recovery_kek, mek),
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
    kek = derive_key(body.master_password, user["kdf_salt"])
    try:
        mek = unwrap_key(kek, user["master_wrapped_mek"])
    except InvalidTag:
        # Bcrypt accepted the password but the wrap doesn't open — treat as a
        # failed login so an attacker can't distinguish the two cases.
        limiter.record_failure(body.username)
        raise AuthError()
    limiter.clear(body.username)
    sid = sessions.create(user_id=user["id"], key=mek)
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
