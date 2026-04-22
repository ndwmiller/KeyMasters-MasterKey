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


def test_404_html_when_accept_html(client):
    r = client.get("/no-such-page", headers={"Accept": "text/html"})
    assert r.status_code == 404
    assert "text/html" in r.headers.get("content-type", "").lower()
    assert "404" in r.text
    # Generic error HTML — shouldn't leak server paths or stack traces
    assert "Traceback" not in r.text


def test_404_json_when_accept_json(client):
    r = client.get("/no-such-page", headers={"Accept": "application/json"})
    assert r.status_code == 404
    assert "application/json" in r.headers.get("content-type", "").lower()
    assert r.json() == {"detail": "Not Found"}  # FastAPI default detail


def test_500_html_does_not_leak_internals():
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.testclient import TestClient
    from app.errors import register_error_handlers
    from pathlib import Path
    from fastapi.templating import Jinja2Templates

    root = Path(__file__).resolve().parent.parent
    app = FastAPI()
    app.state.templates = Jinja2Templates(directory=str(root / "templates"))
    # base.html references url_for('static', ...), so mount it in the test app.
    app.mount("/static", StaticFiles(directory=str(root / "static")), name="static")
    register_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret: should not leak")

    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get("/boom", headers={"Accept": "text/html"})
    assert r.status_code == 500
    assert "secret: should not leak" not in r.text
    assert "500" in r.text or "Something went wrong" in r.text
