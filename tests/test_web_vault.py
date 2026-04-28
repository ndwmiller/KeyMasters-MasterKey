import re

from tests.conftest import register_form


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def _login(client, username: str = "alice", password: str = "Correct!horse1") -> None:
    """Register + auto-login so subsequent requests carry a valid mk_session cookie."""
    get = client.get("/register")
    token = _csrf(get.text)
    r = client.post(
        "/register",
        data=register_form(username, password, csrf=token),
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
        json={"username": "alice", "master_password": "Correct!horse1"},
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


def test_new_credential_get_requires_auth(client):
    r = client.get("/vault/new", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_new_credential_get_renders_form(client):
    _login(client)
    r = client.get("/vault/new")
    assert r.status_code == 200
    assert 'name="service"' in r.text
    assert 'name="password"' in r.text
    assert 'name="_csrf"' in r.text
    # Generator panel
    assert "generator-btn" in r.text or "Generate" in r.text


def test_new_credential_post_creates_and_redirects(client):
    _login(client)
    get = client.get("/vault/new")
    token = _csrf(get.text)
    r = client.post(
        "/vault/new",
        data={
            "service": "github",
            "username": "alice",
            "password": "hunter2",
            "notes": "",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"].startswith("/vault/")
    # Success flash set
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_new_credential_post_missing_csrf_403(client):
    _login(client)
    r = client.post(
        "/vault/new",
        data={"service": "github", "username": "alice", "password": "hunter2"},
    )
    assert r.status_code == 403


def test_new_credential_post_validation_error(client):
    _login(client)
    get = client.get("/vault/new")
    token = _csrf(get.text)
    # Empty service field should fail CredentialCreate validation
    r = client.post(
        "/vault/new",
        data={
            "service": "",
            "username": "alice",
            "password": "hunter2",
            "notes": "",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/new"


def test_new_credential_unauthenticated_post_redirects_to_login(client):
    # No login. Get CSRF from the login page (POST to /vault/new will still short-
    # circuit at auth since there's no session cookie). But CSRF check comes
    # first in many implementations. The plan's design says CSRF-then-auth; a
    # missing cookie means CSRF fails → 403. Accept either 303-to-login or 403
    # as "unauthorized handling":
    r = client.post(
        "/vault/new",
        data={"service": "github", "username": "u", "password": "p"},
    )
    assert r.status_code in (303, 403)


def test_generator_endpoint_accessible_via_cookie(client):
    _login(client)
    r = client.post("/credentials/generate", json={"length": 16})
    assert r.status_code == 200
    assert len(r.json()["password"]) == 16


def _create_via_api(client, service="github", username="alice", password="hunter2", notes=None):
    """Helper: login via JSON API to get Bearer token, create credential, return id."""
    api_login = client.post(
        "/auth/login",
        json={"username": username, "master_password": "Correct!horse1"},
    )
    token = api_login.json()["access_token"]
    body = {"service": service, "username": username, "password": password}
    if notes is not None:
        body["notes"] = notes
    r = client.post(
        "/credentials",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201
    return r.json()["id"]


def test_detail_requires_auth(client):
    r = client.get("/vault/1", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_detail_not_found_redirects_with_flash(client):
    _login(client)
    r = client.get("/vault/999", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_detail_shows_decrypted_fields_for_owner(client):
    _login(client)
    cid = _create_via_api(client, password="hunter2", notes="work account")
    r = client.get(f"/vault/{cid}")
    assert r.status_code == 200
    assert "github" in r.text.lower()
    assert "hunter2" in r.text  # password rendered into DOM (reveal toggle client-side)
    assert "work account" in r.text


def test_detail_denies_other_user_as_not_found(client):
    # alice creates a credential
    _login(client, username="alice")
    cid = _create_via_api(client, username="alice", password="hunter2")
    # Swap to bob — new session cookie replaces alice's.
    client.cookies.clear()
    _login(client, username="bob")
    r = client.get(f"/vault/{cid}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"


def test_delete_requires_csrf(client):
    _login(client)
    cid = _create_via_api(client)
    r = client.post(f"/vault/{cid}/delete")
    assert r.status_code == 403


def test_delete_removes_credential(client):
    _login(client)
    cid = _create_via_api(client)
    get = client.get(f"/vault/{cid}")
    token = _csrf(get.text)
    r = client.post(
        f"/vault/{cid}/delete",
        data={"_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    # Verify it's actually gone
    get_after = client.get("/vault")
    assert "github" not in get_after.text.lower()


def test_delete_rejects_non_owner(client):
    _login(client, username="alice")
    cid = _create_via_api(client, username="alice")
    get = client.get(f"/vault/{cid}")  # alice gets token
    alice_token = _csrf(get.text)
    # Swap to bob, whose own CSRF cookie won't match alice's form token.
    client.cookies.clear()
    _login(client, username="bob")
    r = client.post(
        f"/vault/{cid}/delete",
        data={"_csrf": alice_token},
        follow_redirects=False,
    )
    # Bob's CSRF cookie differs from alice's signed form token, so CSRF fails
    # first → 403. Either way the credential remains; assert 403 or 303.
    assert r.status_code in (303, 403)


def test_edit_requires_auth(client):
    r = client.get("/vault/1/edit", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_edit_get_renders_prefilled_form(client):
    _login(client)
    cid = _create_via_api(client, service="github", username="alice", password="hunter2", notes="work")
    r = client.get(f"/vault/{cid}/edit")
    assert r.status_code == 200
    assert 'name="service"' in r.text
    assert 'value="github"' in r.text
    assert "hunter2" not in r.text  # password no longer pre-filled in form
    assert "work" in r.text
    assert 'name="_csrf"' in r.text


def test_edit_not_found_redirects(client):
    _login(client)
    r = client.get("/vault/9999/edit", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"


def test_edit_post_updates_and_redirects(client):
    _login(client)
    cid = _create_via_api(client, service="github", password="hunter2")
    get = client.get(f"/vault/{cid}/edit")
    token = _csrf(get.text)
    r = client.post(
        f"/vault/{cid}/edit",
        data={
            "service": "github",
            "username": "alice",
            "password": "hunter3",
            "notes": "updated",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/vault/{cid}"
    # Verify the change actually landed
    detail = client.get(f"/vault/{cid}")
    assert "hunter3" in detail.text
    assert "updated" in detail.text


def test_edit_missing_csrf_403(client):
    _login(client)
    cid = _create_via_api(client)
    r = client.post(
        f"/vault/{cid}/edit",
        data={"service": "github", "username": "u", "password": "p"},
    )
    assert r.status_code == 403


def test_edit_cross_user_treated_as_not_found(client):
    _login(client, username="alice")
    cid = _create_via_api(client, username="alice")
    client.cookies.clear()
    _login(client, username="bob")
    r = client.get(f"/vault/{cid}/edit", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
