import re


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def test_full_html_journey(client):
    # 1. Register
    token = _csrf(client.get("/register").text)
    r = client.post(
        "/register",
        data={
            "username": "alice",
            "master_password": "Correct!horse1",
            "confirm_password": "Correct!horse1",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"

    # 2. Vault is empty
    vault = client.get("/vault")
    assert vault.status_code == 200
    assert "vault is empty" in vault.text.lower() or "0 credential" in vault.text.lower()

    # 3. Create credential via HTML form
    new_page = client.get("/vault/new")
    token = _csrf(new_page.text)
    r = client.post(
        "/vault/new",
        data={
            "service": "github",
            "username": "alice@example.com",
            "password": "hunter2",
            "notes": "work",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    cid = int(r.headers["location"].rsplit("/", 1)[-1])

    # 4. Detail shows decrypted fields
    detail = client.get(f"/vault/{cid}")
    assert detail.status_code == 200
    assert "github" in detail.text.lower()
    assert "hunter2" in detail.text
    assert "alice@example.com" in detail.text
    assert "work" in detail.text

    # 5. Edit credential
    edit_page = client.get(f"/vault/{cid}/edit")
    token = _csrf(edit_page.text)
    r = client.post(
        f"/vault/{cid}/edit",
        data={
            "service": "github",
            "username": "alice@example.com",
            "password": "hunter3",  # password rotated
            "notes": "personal account",
            "_csrf": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/vault/{cid}"

    # 6. Detail reflects the update
    detail_after = client.get(f"/vault/{cid}")
    assert "hunter3" in detail_after.text
    assert "personal account" in detail_after.text
    assert "hunter2" not in detail_after.text

    # 7. Vault list now shows the credential
    vault_with_item = client.get("/vault")
    assert "github" in vault_with_item.text.lower()
    assert "1 credential" in vault_with_item.text

    # 8. Logout
    topbar_token = _csrf(vault_with_item.text)
    r = client.post("/logout", data={"_csrf": topbar_token}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"

    # 9. Vault access is gated
    after_logout = client.get("/vault", follow_redirects=False)
    assert after_logout.status_code == 303
    assert "/login" in after_logout.headers["location"]


def test_cross_user_isolation_in_html(client):
    """Alice's credential must be invisible to Bob through the HTML UI."""
    # Register + create as alice
    alice_csrf = _csrf(client.get("/register").text)
    client.post(
        "/register",
        data={
            "username": "alice",
            "master_password": "Correct!horse1",
            "confirm_password": "Correct!horse1",
            "_csrf": alice_csrf,
        },
        follow_redirects=False,
    )
    new_token = _csrf(client.get("/vault/new").text)
    r = client.post(
        "/vault/new",
        data={
            "service": "alice-secret",
            "username": "alice",
            "password": "onlyalice",
            "notes": "",
            "_csrf": new_token,
        },
        follow_redirects=False,
    )
    cid = int(r.headers["location"].rsplit("/", 1)[-1])

    # Switch users
    client.cookies.clear()
    bob_csrf = _csrf(client.get("/register").text)
    client.post(
        "/register",
        data={
            "username": "bob",
            "master_password": "Correct!horse1",
            "confirm_password": "Correct!horse1",
            "_csrf": bob_csrf,
        },
        follow_redirects=False,
    )

    # Bob's vault list must not leak alice's service name or password
    bob_vault = client.get("/vault")
    assert "alice-secret" not in bob_vault.text
    assert "onlyalice" not in bob_vault.text

    # Bob's direct access to alice's credential ID must redirect to /vault
    r = client.get(f"/vault/{cid}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"

    # Bob cannot edit alice's credential
    r = client.get(f"/vault/{cid}/edit", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
