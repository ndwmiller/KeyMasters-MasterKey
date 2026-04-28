import pytest
from fastapi.testclient import TestClient

from app.db.connection import init_schema
from app.main import create_app


# Default recovery payload used by every test that registers a user. Tests that
# care about specific questions/answers can override per-call.
DEFAULT_Q1 = "What was the name of your first pet?"
DEFAULT_A1 = "Fluffy"
DEFAULT_Q2 = "In what city were you born?"
DEFAULT_A2 = "Boston"


def register_payload(
    username: str = "alice",
    password: str = "Correct!horse1",
    *,
    q1: str = DEFAULT_Q1,
    a1: str = DEFAULT_A1,
    q2: str = DEFAULT_Q2,
    a2: str = DEFAULT_A2,
) -> dict[str, str]:
    """JSON body for POST /auth/register."""
    return {
        "username": username,
        "master_password": password,
        "recovery_q1": q1,
        "recovery_a1": a1,
        "recovery_q2": q2,
        "recovery_a2": a2,
    }


def register_form(
    username: str = "alice",
    password: str = "Correct!horse1",
    *,
    confirm: str | None = None,
    csrf: str = "",
    q1: str = DEFAULT_Q1,
    a1: str = DEFAULT_A1,
    q2: str = DEFAULT_Q2,
    a2: str = DEFAULT_A2,
) -> dict[str, str]:
    """Form body for POST /register (HTML)."""
    return {
        "username": username,
        "master_password": password,
        "confirm_password": password if confirm is None else confirm,
        "recovery_q1": q1,
        "recovery_a1": a1,
        "recovery_q2": q2,
        "recovery_a2": a2,
        "_csrf": csrf,
    }


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = str(tmp_path / "test.sqlite")
    monkeypatch.setenv("DB_PATH", path)
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    init_schema(path)
    return path


@pytest.fixture
def client(db_path) -> TestClient:
    return TestClient(create_app())
