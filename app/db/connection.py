# manages the sqlite connection and schema setup
# connect() is a context manager that handles commits, rollbacks, and closing automatically

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  bcrypt_hash BLOB NOT NULL,
  kdf_salt BLOB NOT NULL,
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

# recreated when the old plaintext service column is detected
_CREDENTIALS_DDL = """
DROP TABLE IF EXISTS credentials;
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
        cols = {row[1] for row in conn.execute("PRAGMA table_info(credentials)").fetchall()}
        if "service" in cols:
            conn.executescript(_CREDENTIALS_DDL)
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
