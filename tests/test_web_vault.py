import re


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def _login(client, username: str = "alice", password: str = "correct horse battery") -> None:
    """Register + auto-login so subsequent requests carry a valid mk_session cookie."""
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post(
        "/register",
        data={
            "username": username,
            "master_password": password,
            "confirm_password": password,
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_vault_redirects_to_login_when_unauthenticated(client):
    r = client.get("/vault", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]
    assert "reason=required" in r.headers["location"]


def test_vault_renders_empty_state_for_new_user(client):
    _login(client)
    r = client.get("/vault")
    assert r.status_code == 200
    assert "vault is empty" in r.text.lower() or "0 credential" in r.text.lower()


def test_vault_lists_credentials_for_authenticated_user(client):
    _login(client)
    # Create a credential via the JSON API; we need a Bearer token for that,
    # so log in through the API to mint one. Both transports share the same
    # SessionStore, so the cookie from _login() and the Bearer token from
    # /auth/login are independently valid.
    api_login = client.post(
        "/auth/login",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    token = api_login.json()["access_token"]
    client.post(
        "/credentials",
        json={"service": "github", "username": "alice", "password": "hunter2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    r = client.get("/vault")
    assert r.status_code == 200
    assert "github" in r.text.lower()
    assert "hunter2" not in r.text  # plaintext must not appear
    assert "1 credential" in r.text


def test_vault_root_redirects_to_vault_when_authenticated(client):
    _login(client)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"


def test_root_redirects_to_login_when_unauthenticated(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
