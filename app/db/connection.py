# manages the sqlite connection and schema setup
# connect() is a context manager that handles commits, rollbacks, and closing automatically

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# users.kdf_salt is the salt for the master-password KEK.
# users.master_wrapped_mek holds the per-user Master Encryption Key (MEK), encrypted
# with that KEK. Credentials are encrypted with the MEK, NOT the KEK directly,
# so changing the master password only re-wraps the MEK and credentials don't
# need to be re-encrypted.
# users.recovery_salt + recovery_wrapped_mek encode the same MEK encrypted with
# a KEK derived from the user's normalized security-question answers.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  bcrypt_hash BLOB NOT NULL,
  kdf_salt BLOB NOT NULL,
  master_wrapped_mek BLOB NOT NULL,
  recovery_salt BLOB NOT NULL,
  recovery_q1 TEXT NOT NULL,
  recovery_q2 TEXT NOT NULL,
  recovery_wrapped_mek BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_enc BLOB NOT NULL,
  username_enc BLOB NOT NULL,
  password_enc BLOB NOT NULL,
  notes_enc BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_credentials_user ON credentials(user_id);
"""

# Recreated when the schema is missing the recovery/MEK columns. The data model
# changed shape; cleanly drop both tables so old credentials encrypted under
# the previous direct-KEK scheme don't linger as undecryptable rows.
_RESET_DDL = """
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  bcrypt_hash BLOB NOT NULL,
  kdf_salt BLOB NOT NULL,
  master_wrapped_mek BLOB NOT NULL,
  recovery_salt BLOB NOT NULL,
  recovery_q1 TEXT NOT NULL,
  recovery_q2 TEXT NOT NULL,
  recovery_wrapped_mek BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_enc BLOB NOT NULL,
  username_enc BLOB NOT NULL,
  password_enc BLOB NOT NULL,
  notes_enc BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_credentials_user ON credentials(user_id);
"""


def init_schema(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "master_wrapped_mek" not in user_cols or "recovery_wrapped_mek" not in user_cols:
            conn.executescript(_RESET_DDL)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def connect(db_path: str) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    # overwrites freed bytes with 0s before releasing the page
    conn.execute("PRAGMA secure_delete = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
