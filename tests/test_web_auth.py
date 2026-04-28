import re

from tests.conftest import register_form, register_payload


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def _register_api(client, username: str = "alice", password: str = "Correct!horse1") -> None:
    """Uses the JSON API to create a user (no HTML register route yet in Task 3)."""
    r = client.post("/auth/register", json=register_payload(username, password))
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
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": token},
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


def test_required_reason_shows_flash(client):
    r = client.get("/login?reason=required")
    assert r.status_code == 200
    assert "unlock the vault" in r.text.lower()


def test_register_get_renders_form(client):
    r = client.get("/register")
    assert r.status_code == 200
    assert "Forge Your Key" in r.text or "Create Master Account" in r.text
    assert 'name="_csrf"' in r.text
    assert 'name="username"' in r.text
    assert 'name="master_password"' in r.text
    assert 'name="confirm_password"' in r.text


def test_register_post_happy_auto_login(client):
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post("/register", data=register_form(csrf=token), follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "mk_session=" in set_cookie
    assert "httponly" in set_cookie


def test_register_post_mismatched_passwords(client):
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post(
        "/register",
        data=register_form(csrf=token, confirm="different password here"),
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/register"
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_register_post_short_password(client):
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post(
        "/register",
        data=register_form(csrf=token, password="short"),
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/register"
    # Flash should explain validation failed.
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_register_post_duplicate_username(client):
    # Create alice first via the JSON API.
    _register_api(client)
    # Now try to register alice through the HTML form.
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post("/register", data=register_form(csrf=token), follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/register"
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_register_post_missing_csrf_403(client):
    # CSRF token field omitted → CSRF middleware should reject.
    payload = register_form(csrf="")
    payload.pop("_csrf")
    r = client.post("/register", data=payload)
    assert r.status_code == 403


def test_csrf_cookie_stable_across_page_navigations(client):
    # Regression: navigating GET /login -> GET /register must NOT rotate the
    # CSRF cookie. Previously every render minted a fresh token and
    # overwrote the cookie, desyncing from the form token still held by
    # earlier-rendered pages (back-button / multi-tab). That broke POST /login.
    _register_api(client)
    get_login = client.get("/login")
    form_token = _csrf(get_login.text)
    # User clicks "register" then goes back to the login tab.
    client.get("/register")
    r = client.post(
        "/login",
        data={
            "username": "alice",
            "master_password": "Correct!horse1",
            "_csrf": form_token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"


def test_logout_csrf_required(client):
    r = client.post("/logout", data={})
    assert r.status_code == 403


def test_logout_clears_session_and_redirects(client):
    _register_api(client)
    # Login via HTML to establish cookies
    get = client.get("/login")
    token = _csrf(get.text)
    login = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": token},
        follow_redirects=False,
    )
    assert login.status_code == 303
    # Grab a fresh CSRF token from a page that has one (e.g. /login again, or /vault)
    vault = client.get("/vault")
    assert vault.status_code == 200
    # The vault list has a logout form in the topbar — extract its CSRF
    logout_token = _csrf(vault.text)
    r = client.post(
        "/logout",
        data={"_csrf": logout_token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert 'mk_session=""' in set_cookie or "mk_session=;" in set_cookie
    # Accessing /vault after logout → redirect back to login
    after = client.get("/vault", follow_redirects=False)
    assert after.status_code == 303
    assert "/login" in after.headers["location"]
