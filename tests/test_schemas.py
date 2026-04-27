import pytest
from pydantic import ValidationError

from app.schemas.credential import CredentialCreate, CredentialUpdate
from app.schemas.user import LoginRequest, RegisterRequest


_GOOD_PW = "Correct!horse1"  # meets all rules: upper, lower, symbol, 12+ chars


def test_register_requires_min_password_length():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="short")
    ok = RegisterRequest(username="alice", master_password=_GOOD_PW)
    assert ok.username == "alice"


def test_register_rejects_missing_uppercase():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="nouppercase!1")


def test_register_rejects_missing_lowercase():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="NOLOWERCASE!1")


def test_register_rejects_missing_symbol():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="NoSymbolHere12")


def test_register_rejects_empty_username():
    with pytest.raises(ValidationError):
        RegisterRequest(username="", master_password=_GOOD_PW)


def test_register_strips_whitespace_username():
    r = RegisterRequest(username="  alice  ", master_password=_GOOD_PW)
    assert r.username == "alice"


def test_login_accepts_any_nonempty_password():
    LoginRequest(username="alice", master_password="anything")


def test_credential_create_requires_service():
    with pytest.raises(ValidationError):
        CredentialCreate(service="", username="u", password="p")
    ok = CredentialCreate(service="github", username="u", password="p")
    assert ok.notes is None


def test_credential_update_all_optional():
    CredentialUpdate()
    CredentialUpdate(service="x")
