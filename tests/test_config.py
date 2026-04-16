import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_load_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.sqlite"))
    s = Settings()
    assert s.jwt_secret == "x" * 32
    assert s.jwt_algorithm == "HS256"
    assert s.jwt_ttl_minutes == 15
    assert s.bcrypt_cost == 12


def test_settings_reject_short_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(ValidationError):
        Settings()
