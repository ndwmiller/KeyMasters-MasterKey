from fastapi.testclient import TestClient

from app.main import create_app


def test_headers_on_html_response(client):
    r = client.get("/health")
    assert "Content-Security-Policy" in r.headers
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "Permissions-Policy" in r.headers
    assert "geolocation=()" in r.headers["Permissions-Policy"]
    assert "camera=()" in r.headers["Permissions-Policy"]
    assert "microphone=()" in r.headers["Permissions-Policy"]
    assert "Strict-Transport-Security" not in r.headers


def test_hsts_present_on_https(db_path):
    client = TestClient(create_app(), base_url="https://testserver")
    r = client.get("/health")
    assert "Strict-Transport-Security" in r.headers
    assert "max-age=63072000" in r.headers["Strict-Transport-Security"]
    assert "includeSubDomains" in r.headers["Strict-Transport-Security"]
