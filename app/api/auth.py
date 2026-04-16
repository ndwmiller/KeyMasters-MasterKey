import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from app.auth.kdf import new_salt
from app.auth.password import hash_master_password
from app.config import get_settings
from app.db import repository as repo
from app.schemas.user import RegisterRequest, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


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
