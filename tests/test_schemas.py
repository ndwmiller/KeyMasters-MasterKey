import pytest
from pydantic import ValidationError

from app.schemas.credential import CredentialCreate, CredentialUpdate
from app.schemas.user import LoginRequest, RegisterRequest


_GOOD_PW = "Correct!horse1"  # meets all rules: upper, lower, symbol, 12+ chars
_DEFAULTS = dict(
    recovery_q1="What was the name of your first pet?",
    recovery_a1="Fluffy",
    recovery_q2="In what city were you born?",
    recovery_a2="Boston",
)


def test_register_requires_min_password_length():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="Sh0rt!", **_DEFAULTS)
    ok = RegisterRequest(username="alice", master_password=_GOOD_PW, **_DEFAULTS)
    assert ok.username == "alice"


def test_register_rejects_missing_uppercase():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="nouppercase!1", **_DEFAULTS)


def test_register_rejects_missing_lowercase():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="NOLOWERCASE!1", **_DEFAULTS)


def test_register_rejects_missing_symbol():
    with pytest.raises(ValidationError):
        RegisterRequest(username="alice", master_password="NoSymbolHere12", **_DEFAULTS)


def test_register_rejects_empty_username():
    with pytest.raises(ValidationError):
        RegisterRequest(username="", master_password=_GOOD_PW, **_DEFAULTS)


def test_register_strips_whitespace_username():
    r = RegisterRequest(username="  alice  ", master_password=_GOOD_PW, **_DEFAULTS)
    assert r.username == "alice"


def test_register_rejects_unknown_question():
    with pytest.raises(ValidationError):
        RegisterRequest(
            username="alice",
            master_password=_GOOD_PW,
            recovery_q1="What is the airspeed velocity of an unladen swallow?",
            recovery_a1="african or european",
            recovery_q2="In what city were you born?",
            recovery_a2="Boston",
        )


def test_register_rejects_duplicate_questions():
    with pytest.raises(ValidationError):
        RegisterRequest(
            username="alice",
            master_password=_GOOD_PW,
            recovery_q1="In what city were you born?",
            recovery_a1="Boston",
            recovery_q2="In what city were you born?",
            recovery_a2="Boston",
        )


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
