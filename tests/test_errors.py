from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.errors import AuthError, register_error_handlers


def _app() -> TestClient:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/a")
    def a():
        raise AuthError()

    @app.get("/b")
    def b():
        raise RuntimeError("internal detail that must not leak")

    return TestClient(app, raise_server_exceptions=False)


def test_auth_error_generic_401():
    r = _app().get("/a")
    assert r.status_code == 401
    assert r.json() == {"detail": "authentication failed"}


def test_unexpected_error_generic_500_no_leak():
    r = _app().get("/b")
    assert r.status_code == 500
    assert r.json() == {"detail": "internal error"}
    assert "internal detail" not in r.text
