import pytest
from fastapi.testclient import TestClient

from app.db.connection import init_schema
from app.main import create_app


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
