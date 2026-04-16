import sqlite3
from datetime import datetime, timezone

import pytest

from app.db import repository as repo


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_create_and_fetch_user(db_path):
    uid = repo.create_user(
        db_path,
        username="alice",
        bcrypt_hash=b"$2b$12$abc",
        kdf_salt=b"\x00" * 16,
        created_at=iso_now(),
    )
    assert uid > 0
    row = repo.get_user_by_username(db_path, "alice")
    assert row is not None
    assert row["username"] == "alice"
    assert row["bcrypt_hash"] == b"$2b$12$abc"
    assert row["kdf_salt"] == b"\x00" * 16


def test_get_unknown_user_returns_none(db_path):
    assert repo.get_user_by_username(db_path, "ghost") is None


def test_duplicate_username_raises(db_path):
    repo.create_user(
        db_path, username="a", bcrypt_hash=b"h", kdf_salt=b"s", created_at=iso_now()
    )
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_user(
            db_path, username="a", bcrypt_hash=b"h", kdf_salt=b"s", created_at=iso_now()
        )


def test_credential_round_trip(db_path):
    uid = repo.create_user(
        db_path, username="a", bcrypt_hash=b"h", kdf_salt=b"s", created_at=iso_now()
    )
    cid = repo.create_credential(
        db_path,
        user_id=uid,
        service="github",
        username_enc=b"uenc",
        password_enc=b"penc",
        notes_enc=None,
        created_at=iso_now(),
        updated_at=iso_now(),
    )
    rows = repo.list_credentials_for_user(db_path, uid)
    assert len(rows) == 1
    assert rows[0]["id"] == cid
    full = repo.get_credential(db_path, cid=cid, user_id=uid)
    assert full is not None
    assert full["password_enc"] == b"penc"
    assert repo.get_credential(db_path, cid=cid, user_id=uid + 1) is None
    repo.delete_credential(db_path, cid=cid, user_id=uid)
    assert repo.list_credentials_for_user(db_path, uid) == []
