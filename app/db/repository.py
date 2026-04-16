from typing import Any

from app.db.connection import connect


def create_user(
    db_path: str,
    *,
    username: str,
    bcrypt_hash: bytes,
    kdf_salt: bytes,
    created_at: str,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, bcrypt_hash, kdf_salt, created_at) VALUES (?, ?, ?, ?)",
            (username, bcrypt_hash, kdf_salt, created_at),
        )
        return cur.lastrowid


def get_user_by_username(db_path: str, username: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, username, bcrypt_hash, kdf_salt, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, username, bcrypt_hash, kdf_salt, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def create_credential(
    db_path: str,
    *,
    user_id: int,
    service: str,
    username_enc: bytes,
    password_enc: bytes,
    notes_enc: bytes | None,
    created_at: str,
    updated_at: str,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO credentials (user_id, service, username_enc, password_enc, notes_enc, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, service, username_enc, password_enc, notes_enc, created_at, updated_at),
        )
        return cur.lastrowid


def list_credentials_for_user(db_path: str, user_id: int) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, service, created_at, updated_at FROM credentials WHERE user_id = ? ORDER BY service",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_credential(db_path: str, *, cid: int, user_id: int) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, user_id, service, username_enc, password_enc, notes_enc, created_at, updated_at "
            "FROM credentials WHERE id = ? AND user_id = ?",
            (cid, user_id),
        ).fetchone()
        return dict(row) if row else None


def update_credential(
    db_path: str,
    *,
    cid: int,
    user_id: int,
    service: str,
    username_enc: bytes,
    password_enc: bytes,
    notes_enc: bytes | None,
    updated_at: str,
) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE credentials SET service=?, username_enc=?, password_enc=?, notes_enc=?, updated_at=? "
            "WHERE id = ? AND user_id = ?",
            (service, username_enc, password_enc, notes_enc, updated_at, cid, user_id),
        )
        return cur.rowcount == 1


def delete_credential(db_path: str, *, cid: int, user_id: int) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?",
            (cid, user_id),
        )
        return cur.rowcount == 1
