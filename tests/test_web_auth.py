import re


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def _register_api(client, username: str = "alice", password: str = "correct horse battery") -> None:
    """Uses the JSON API to create a user (no HTML register route yet in Task 3)."""
    r = client.post(
        "/auth/register",
        json={"username": username, "master_password": password},
    )
    assert r.status_code == 201


def test_login_get_renders_form(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Unlock Your Vault" in r.text
    assert 'name="_csrf"' in r.text
    # CSRF cookie set on GET
    assert "mk_csrf=" in r.headers.get("set-cookie", "").lower() or \
           "mk_csrf" in str(r.cookies).lower()


def test_login_post_happy_sets_cookie_and_redirects(client):
    _register_api(client)
    get = client.get("/login")
    token = _csrf(get.text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "correct horse battery", "_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "mk_session=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie


def test_login_post_missing_csrf_403(client):
    _register_api(client)
    r = client.post("/login", data={"username": "alice", "master_password": "x"})
    assert r.status_code == 403


def test_login_post_wrong_csrf_403(client):
    _register_api(client)
    get = client.get("/login")
    token = _csrf(get.text)
    # Use the form token but no matching cookie — test client has the cookie
    # from the GET, so we have to CLEAR it to simulate a forgery attempt.
    client.cookies.clear()
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "x", "_csrf": token},
    )
    assert r.status_code == 403


def test_login_post_wrong_password_generic_flash(client):
    _register_api(client)
    get = client.get("/login")
    token = _csrf(get.text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "nope", "_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    # Flash cookie should be set so the next GET can render the error
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "mk_flash=" in set_cookie


def test_login_post_unknown_user_same_as_wrong_password(client):
    # No user_enum leak: unknown user returns same 303->/login as wrong password.
    get = client.get("/login")
    token = _csrf(get.text)
    r = client.post(
        "/login",
        data={"username": "ghost", "master_password": "nope", "_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_expired_reason_shows_flash(client):
    r = client.get("/login?reason=expired")
    assert r.status_code == 200
    assert "session expired" in r.text.lower()
