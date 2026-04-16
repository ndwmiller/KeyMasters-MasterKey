from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.deps import CurrentSession, get_current_session
from app.auth.jwt import issue_token
from app.auth.session_store import SessionStore
from app.errors import register_error_handlers


def _build_app(store: SessionStore) -> TestClient:
    app = FastAPI()
    app.state.sessions = store
    register_error_handlers(app)

    @app.get("/protected")
    def protected(session: CurrentSession = Depends(get_current_session)) -> dict:
        return {"user_id": session.user_id}

    return TestClient(app)


def test_valid_token_and_session(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=7, key=b"\x00" * 32)
    token = issue_token({"sub": "7", "sid": sid}, "x" * 32)
    client = _build_app(store)
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["user_id"] == 7


def test_missing_header_401(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    client = _build_app(SessionStore(ttl_seconds=60))
    r = client.get("/protected")
    assert r.status_code == 401


def test_bad_token_401(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    client = _build_app(SessionStore(ttl_seconds=60))
    r = client.get("/protected", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_revoked_session_401(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    token = issue_token({"sub": "7", "sid": "not-in-store"}, "x" * 32)
    client = _build_app(store)
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_cookie_auth_works(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    token = issue_token({"sub": "9", "sid": sid}, "x" * 32)
    client = _build_app(store)
    client.cookies.set("mk_session", token)
    r = client.get("/protected")
    assert r.status_code == 200
    assert r.json()["user_id"] == 9


def test_header_wins_over_cookie(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    good = issue_token({"sub": "9", "sid": sid}, "x" * 32)
    client = _build_app(store)
    client.cookies.set("mk_session", "garbage")
    r = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {good}"},
    )
    assert r.status_code == 200


def test_expired_cookie_token_rejected(monkeypatch):
    from datetime import timedelta
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    expired = issue_token({"sub": "9", "sid": sid}, "x" * 32, ttl=timedelta(seconds=-1))
    client = _build_app(store)
    client.cookies.set("mk_session", expired)
    r = client.get("/protected")
    assert r.status_code == 401


def test_malformed_bearer_does_not_fall_back_to_cookie(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    good = issue_token({"sub": "9", "sid": sid}, "x" * 32)
    client = _build_app(store)
    client.cookies.set("mk_session", good)
    r = client.get("/protected", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401
