from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentSession, get_current_session
from app.config import get_settings
from app.crypto.encryption import decrypt_credential, encrypt_credential
from app.db import repository as repo
from app.errors import NotFoundError
from app.schemas.credential import (
    CredentialCreate,
    CredentialFull,
    CredentialMeta,
    CredentialUpdate,
)
from app.services.password_gen import generate_password

router = APIRouter(prefix="/credentials", tags=["credentials"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt_fields(
    key: bytes, username: str, password: str, notes: str | None
) -> tuple[bytes, bytes, bytes | None]:
    return (
        encrypt_credential(key, username),
        encrypt_credential(key, password),
        encrypt_credential(key, notes) if notes is not None else None,
    )


def _decrypt_row(key: bytes, row: dict) -> CredentialFull:
    return CredentialFull(
        id=row["id"],
        service=row["service"],
        username=decrypt_credential(key, row["username_enc"]),
        password=decrypt_credential(key, row["password_enc"]),
        notes=decrypt_credential(key, row["notes_enc"]) if row["notes_enc"] is not None else None,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class GenerateRequest(BaseModel):
    length: int = Field(default=20, ge=8, le=128)


class GenerateResponse(BaseModel):
    password: str


@router.post("/generate", response_model=GenerateResponse)
def generate(
    body: GenerateRequest,
    _: CurrentSession = Depends(get_current_session),
) -> GenerateResponse:
    return GenerateResponse(password=generate_password(length=body.length))


@router.post("", response_model=CredentialMeta, status_code=status.HTTP_201_CREATED)
def create(
    body: CredentialCreate,
    session: CurrentSession = Depends(get_current_session),
) -> CredentialMeta:
    u_enc, p_enc, n_enc = _encrypt_fields(session.key, body.username, body.password, body.notes)
    now = _now()
    cid = repo.create_credential(
        get_settings().db_path,
        user_id=session.user_id,
        service=body.service,
        username_enc=u_enc,
        password_enc=p_enc,
        notes_enc=n_enc,
        created_at=now,
        updated_at=now,
    )
    return CredentialMeta(id=cid, service=body.service, created_at=now, updated_at=now)


@router.get("", response_model=list[CredentialMeta])
def list_(session: CurrentSession = Depends(get_current_session)) -> list[CredentialMeta]:
    rows = repo.list_credentials_for_user(get_settings().db_path, session.user_id)
    return [CredentialMeta(**r) for r in rows]


@router.get("/{cid}", response_model=CredentialFull)
def get(cid: int, session: CurrentSession = Depends(get_current_session)) -> CredentialFull:
    row = repo.get_credential(get_settings().db_path, cid=cid, user_id=session.user_id)
    if row is None:
        raise NotFoundError()
    return _decrypt_row(session.key, row)


@router.put("/{cid}", response_model=CredentialFull)
def update(
    cid: int,
    body: CredentialUpdate,
    session: CurrentSession = Depends(get_current_session),
) -> CredentialFull:
    existing = repo.get_credential(get_settings().db_path, cid=cid, user_id=session.user_id)
    if existing is None:
        raise NotFoundError()
    current = _decrypt_row(session.key, existing)
    merged_service = body.service if body.service is not None else current.service
    merged_username = body.username if body.username is not None else current.username
    merged_password = body.password if body.password is not None else current.password
    merged_notes = body.notes if body.notes is not None else current.notes
    u_enc, p_enc, n_enc = _encrypt_fields(
        session.key, merged_username, merged_password, merged_notes
    )
    now = _now()
    repo.update_credential(
        get_settings().db_path,
        cid=cid,
        user_id=session.user_id,
        service=merged_service,
        username_enc=u_enc,
        password_enc=p_enc,
        notes_enc=n_enc,
        updated_at=now,
    )
    return CredentialFull(
        id=cid,
        service=merged_service,
        username=merged_username,
        password=merged_password,
        notes=merged_notes,
        created_at=current.created_at,
        updated_at=now,
    )


@router.delete("/{cid}", status_code=204)
def delete(cid: int, session: CurrentSession = Depends(get_current_session)) -> None:
    ok = repo.delete_credential(get_settings().db_path, cid=cid, user_id=session.user_id)
    if not ok:
        raise NotFoundError()
