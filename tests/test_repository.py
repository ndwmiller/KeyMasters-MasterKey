import sqlite3
from datetime import datetime, timezone

import pytest

from app.db import repository as repo


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _user_kwargs(**overrides):
    base = dict(
        username="alice",
        bcrypt_hash=b"$2b$12$abc",
        kdf_salt=b"\x00" * 16,
        master_wrapped_mek=b"\x00" * 60,
        recovery_salt=b"\x11" * 16,
        recovery_q1="What was the name of your first pet?",
        recovery_q2="In what city were you born?",
        recovery_wrapped_mek=b"\x22" * 60,
        created_at=iso_now(),
    )
    base.update(overrides)
    return base


def test_create_and_fetch_user(db_path):
    uid = repo.create_user(db_path, **_user_kwargs())
    assert uid > 0
    row = repo.get_user_by_username(db_path, "alice")
    assert row is not None
    assert row["username"] == "alice"
    assert row["bcrypt_hash"] == b"$2b$12$abc"
    assert row["kdf_salt"] == b"\x00" * 16
    assert row["master_wrapped_mek"] == b"\x00" * 60
    assert row["recovery_q1"] == "What was the name of your first pet?"
    assert row["recovery_wrapped_mek"] == b"\x22" * 60


def test_get_unknown_user_returns_none(db_path):
    assert repo.get_user_by_username(db_path, "ghost") is None


def test_duplicate_username_raises(db_path):
    repo.create_user(db_path, **_user_kwargs(username="a"))
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_user(db_path, **_user_kwargs(username="a"))


def test_credential_round_trip(db_path):
    uid = repo.create_user(db_path, **_user_kwargs(username="a"))
    cid = repo.create_credential(
        db_path,
        user_id=uid,
        service_enc=b"senc",
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
    assert full["service_enc"] == b"senc"
    assert full["password_enc"] == b"penc"
    assert repo.get_credential(db_path, cid=cid, user_id=uid + 1) is None
    repo.delete_credential(db_path, cid=cid, user_id=uid)
    assert repo.list_credentials_for_user(db_path, uid) == []


def test_update_user_master_password(db_path):
    uid = repo.create_user(db_path, **_user_kwargs(username="a"))
    ok = repo.update_user_master_password(
        db_path,
        user_id=uid,
        bcrypt_hash=b"$2b$12$new",
        kdf_salt=b"\xaa" * 16,
        master_wrapped_mek=b"\xbb" * 60,
    )
    assert ok is True
    row = repo.get_user_by_id(db_path, uid)
    assert row["bcrypt_hash"] == b"$2b$12$new"
    assert row["kdf_salt"] == b"\xaa" * 16
    assert row["master_wrapped_mek"] == b"\xbb" * 60


def test_update_user_recovery(db_path):
    uid = repo.create_user(db_path, **_user_kwargs(username="a"))
    ok = repo.update_user_recovery(
        db_path,
        user_id=uid,
        recovery_salt=b"\xcc" * 16,
        recovery_q1="What is your mother's maiden name?",
        recovery_q2="What was the make of your first car?",
        recovery_wrapped_mek=b"\xdd" * 60,
    )
    assert ok is True
    row = repo.get_user_by_id(db_path, uid)
    assert row["recovery_q1"] == "What is your mother's maiden name?"
    assert row["recovery_wrapped_mek"] == b"\xdd" * 60


def test_delete_user_cascades_credentials(db_path):
    uid = repo.create_user(db_path, **_user_kwargs(username="a"))
    repo.create_credential(
        db_path,
        user_id=uid,
        service_enc=b"s",
        username_enc=b"u",
        password_enc=b"p",
        notes_enc=None,
        created_at=iso_now(),
        updated_at=iso_now(),
    )
    assert repo.delete_user(db_path, user_id=uid) is True
    assert repo.get_user_by_id(db_path, uid) is None
    assert repo.list_credentials_for_user(db_path, uid) == []
