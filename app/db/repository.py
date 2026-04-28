# all database access goes through here, no sql exists anywhere else in the app
# every query that touches credentials filters by user_id to prevent one user reading another's data

from typing import Any

from app.db.connection import connect


def create_user(
    db_path: str,
    *,
    username: str,
    bcrypt_hash: bytes,
    kdf_salt: bytes,
    master_wrapped_mek: bytes,
    recovery_salt: bytes,
    recovery_q1: str,
    recovery_q2: str,
    recovery_wrapped_mek: bytes,
    created_at: str,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users ("
            "  username, bcrypt_hash, kdf_salt,"
            "  master_wrapped_mek, recovery_salt,"
            "  recovery_q1, recovery_q2, recovery_wrapped_mek,"
            "  created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                bcrypt_hash,
                kdf_salt,
                master_wrapped_mek,
                recovery_salt,
                recovery_q1,
                recovery_q2,
                recovery_wrapped_mek,
                created_at,
            ),
        )
        return cur.lastrowid


_USER_FIELDS = (
    "id, username, bcrypt_hash, kdf_salt,"
    " master_wrapped_mek, recovery_salt,"
    " recovery_q1, recovery_q2, recovery_wrapped_mek,"
    " created_at"
)


def get_user_by_username(db_path: str, username: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {_USER_FIELDS} FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {_USER_FIELDS} FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def update_user_master_password(
    db_path: str,
    *,
    user_id: int,
    bcrypt_hash: bytes,
    kdf_salt: bytes,
    master_wrapped_mek: bytes,
) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE users SET bcrypt_hash = ?, kdf_salt = ?, master_wrapped_mek = ? WHERE id = ?",
            (bcrypt_hash, kdf_salt, master_wrapped_mek, user_id),
        )
        return cur.rowcount == 1


def update_user_recovery(
    db_path: str,
    *,
    user_id: int,
    recovery_salt: bytes,
    recovery_q1: str,
    recovery_q2: str,
    recovery_wrapped_mek: bytes,
) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE users SET recovery_salt = ?, recovery_q1 = ?, recovery_q2 = ?, recovery_wrapped_mek = ? WHERE id = ?",
            (recovery_salt, recovery_q1, recovery_q2, recovery_wrapped_mek, user_id),
        )
        return cur.rowcount == 1


def delete_user(db_path: str, *, user_id: int) -> bool:
    # ON DELETE CASCADE on credentials.user_id removes the user's encrypted rows.
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount == 1


def create_credential(
    db_path: str,
    *,
    user_id: int,
    service_enc: bytes,
    username_enc: bytes,
    password_enc: bytes,
    notes_enc: bytes | None,
    created_at: str,
    updated_at: str,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO credentials (user_id, service_enc, username_enc, password_enc, notes_enc, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, service_enc, username_enc, password_enc, notes_enc, created_at, updated_at),
        )
        return cur.lastrowid


def list_credentials_for_user(db_path: str, user_id: int) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, service_enc, created_at, updated_at FROM credentials WHERE user_id = ? ORDER BY id",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_credential(db_path: str, *, cid: int, user_id: int) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, user_id, service_enc, username_enc, password_enc, notes_enc, created_at, updated_at "
            "FROM credentials WHERE id = ? AND user_id = ?",
            (cid, user_id),
        ).fetchone()
        return dict(row) if row else None


def update_credential(
    db_path: str,
    *,
    cid: int,
    user_id: int,
    service_enc: bytes,
    username_enc: bytes,
    password_enc: bytes,
    notes_enc: bytes | None,
    updated_at: str,
) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE credentials SET service_enc=?, username_enc=?, password_enc=?, notes_enc=?, updated_at=? "
            "WHERE id = ? AND user_id = ?",
            (service_enc, username_enc, password_enc, notes_enc, updated_at, cid, user_id),
        )
        return cur.rowcount == 1


def delete_credential(db_path: str, *, cid: int, user_id: int) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?",
            (cid, user_id),
        )
        return cur.rowcount == 1
