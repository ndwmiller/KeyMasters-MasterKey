"""End-to-end tests for the settings page: change-password, update-questions,
delete-account, plus the public forgot-password recovery flow."""

import re

from tests.conftest import register_form


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m is not None, "CSRF token not found in form"
    return m.group(1)


def _login(client, username: str = "alice", password: str = "Correct!horse1") -> None:
    token = _csrf(client.get("/register").text)
    r = client.post(
        "/register",
        data=register_form(username, password, csrf=token),
        follow_redirects=False,
    )
    assert r.status_code == 303


def _csrf_for_authed(client) -> str:
    return _csrf(client.get("/vault/settings").text)


def _create_credential(client, password: str = "hunter2", service: str = "github") -> int:
    new_csrf = _csrf(client.get("/vault/new").text)
    r = client.post(
        "/vault/new",
        data={
            "service": service,
            "username": "alice@example.com",
            "password": password,
            "notes": "",
            "_csrf": new_csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    return int(r.headers["location"].rsplit("/", 1)[-1])


def test_settings_get_renders_account_and_recovery(client):
    _login(client)
    r = client.get("/vault/settings")
    assert r.status_code == 200
    assert "alice" in r.text
    assert "Change Master Password" in r.text
    assert "Recovery Questions" in r.text
    assert "Danger Zone" in r.text
    assert "Delete Account" in r.text


def test_settings_get_unauthenticated_redirects(client):
    r = client.get("/vault/settings", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_change_password_requires_csrf(client):
    _login(client)
    r = client.post("/vault/settings/change-password", data={
        "current_password": "Correct!horse1",
        "new_password": "new strong password 1",
        "confirm_password": "new strong password 1",
    })
    assert r.status_code == 403


def test_change_password_wrong_current_rejected(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/change-password",
        data={
            "_csrf": token,
            "current_password": "wrong wrong wrong",
            "new_password": "new strong password 1",
            "confirm_password": "new strong password 1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"


def test_change_password_happy_path_keeps_credentials_decryptable(client):
    """The crucial invariant: changing the password must NOT lose existing data."""
    _login(client)
    cid = _create_credential(client, password="hunter2")

    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/change-password",
        data={
            "_csrf": token,
            "current_password": "Correct!horse1",
            "new_password": "BrandN3w!Str0ngKey",
            "confirm_password": "BrandN3w!Str0ngKey",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    # Old password must no longer work; new password must.
    client.cookies.clear()
    login_csrf = _csrf(client.get("/login").text)
    bad = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert bad.status_code == 303
    assert bad.headers["location"] == "/login"
    assert "mk_session=" not in bad.headers.get("set-cookie", "").lower()

    login_csrf = _csrf(client.get("/login").text)
    good = client.post(
        "/login",
        data={"username": "alice", "master_password": "BrandN3w!Str0ngKey", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert good.headers["location"] == "/vault"

    # Existing credential must still decrypt under the new key.
    detail = client.get(f"/vault/{cid}")
    assert detail.status_code == 200
    assert "hunter2" in detail.text
    assert "github" in detail.text.lower()


def test_change_password_too_short(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/change-password",
        data={
            "_csrf": token,
            "current_password": "Correct!horse1",
            "new_password": "short",
            "confirm_password": "short",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"


def test_change_password_rejects_password_without_complexity(client):
    """12+ chars but no uppercase/symbol → reject. Same rules as registration."""
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/change-password",
        data={
            "_csrf": token,
            "current_password": "Correct!horse1",
            "new_password": "alllowercaseonly",
            "confirm_password": "alllowercaseonly",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"
    # Old password still works.
    client.cookies.clear()
    login_csrf = _csrf(client.get("/login").text)
    good = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert good.headers["location"] == "/vault"


def test_update_recovery_questions_changes_recovery_path(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/update-questions",
        data={
            "_csrf": token,
            "current_password": "Correct!horse1",
            "recovery_q1": "What is your mother's maiden name?",
            "recovery_a1": "Smith",
            "recovery_q2": "What was the make of your first car?",
            "recovery_a2": "Honda",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Old answers no longer recover.
    client.cookies.clear()
    forgot_csrf = _csrf(client.get("/forgot-password").text)
    look = client.post("/forgot-password", data={"username": "alice", "_csrf": forgot_csrf}, follow_redirects=False)
    assert look.status_code == 200
    page_csrf = _csrf(look.text)
    bad = client.post(
        "/forgot-password/recover",
        data={
            "_csrf": page_csrf,
            "username": "alice",
            "answer1": "Fluffy",
            "answer2": "Boston",
            "new_password": "new password attempt 1",
            "confirm_password": "new password attempt 1",
        },
        follow_redirects=False,
    )
    assert bad.status_code == 303
    assert bad.headers["location"] == "/forgot-password"


def test_update_recovery_rejects_unknown_question(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/update-questions",
        data={
            "_csrf": token,
            "current_password": "Correct!horse1",
            "recovery_q1": "Made-up question?",
            "recovery_a1": "x",
            "recovery_q2": "What was the make of your first car?",
            "recovery_a2": "Honda",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"


def test_delete_account_wrong_username_rejected(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/delete-account",
        data={
            "_csrf": token,
            "confirm_username": "not-alice",
            "current_password": "Correct!horse1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"
    # Account still exists and login still works.
    client.cookies.clear()
    login_csrf = _csrf(client.get("/login").text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"


def test_delete_account_wrong_password_rejected(client):
    _login(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/delete-account",
        data={
            "_csrf": token,
            "confirm_username": "alice",
            "current_password": "WRONG",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault/settings"


def test_delete_account_happy_path_removes_user_and_credentials(client):
    _login(client)
    _create_credential(client)
    token = _csrf_for_authed(client)
    r = client.post(
        "/vault/settings/delete-account",
        data={
            "_csrf": token,
            "confirm_username": "alice",
            "current_password": "Correct!horse1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "mk_session=" in set_cookie  # cleared cookie

    # Login attempt now fails because the user no longer exists.
    client.cookies.clear()
    login_csrf = _csrf(client.get("/login").text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    assert "mk_session=" not in r.headers.get("set-cookie", "").lower()


def test_forgot_password_get_renders_lookup(client):
    r = client.get("/forgot-password")
    assert r.status_code == 200
    assert "Recover Master Password" in r.text
    assert 'name="username"' in r.text


def test_forgot_password_unknown_user_redirects_with_flash(client):
    forgot_csrf = _csrf(client.get("/forgot-password").text)
    r = client.post("/forgot-password", data={"username": "ghost", "_csrf": forgot_csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/forgot-password"
    assert "mk_flash=" in r.headers.get("set-cookie", "").lower()


def test_forgot_password_full_recovery_resets_master_password(client):
    _login(client)
    cid = _create_credential(client, password="hunter2")
    # Walk away from the session — simulate a forgotten password.
    client.cookies.clear()

    forgot_csrf = _csrf(client.get("/forgot-password").text)
    look = client.post(
        "/forgot-password",
        data={"username": "alice", "_csrf": forgot_csrf},
        follow_redirects=False,
    )
    assert look.status_code == 200
    assert "What was the name of your first pet?" in look.text
    assert "In what city were you born?" in look.text

    page_csrf = _csrf(look.text)
    r = client.post(
        "/forgot-password/recover",
        data={
            "_csrf": page_csrf,
            "username": "alice",
            "answer1": "  fluffy  ",  # case + whitespace tolerant
            "answer2": "BOSTON",
            "new_password": "FreshR3covered!Pass",
            "confirm_password": "FreshR3covered!Pass",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"

    # Log in with the new password and confirm the existing credential still decrypts.
    login_csrf = _csrf(client.get("/login").text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "FreshR3covered!Pass", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    detail = client.get(f"/vault/{cid}")
    assert detail.status_code == 200
    assert "hunter2" in detail.text


def test_forgot_password_wrong_answers_rejected(client):
    _login(client)
    client.cookies.clear()
    forgot_csrf = _csrf(client.get("/forgot-password").text)
    look = client.post("/forgot-password", data={"username": "alice", "_csrf": forgot_csrf}, follow_redirects=False)
    page_csrf = _csrf(look.text)
    r = client.post(
        "/forgot-password/recover",
        data={
            "_csrf": page_csrf,
            "username": "alice",
            "answer1": "wrong",
            "answer2": "answers",
            # Strong new password so we exercise the answer check, not the
            # complexity check.
            "new_password": "ThisShouldN0t!Work",
            "confirm_password": "ThisShouldN0t!Work",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/forgot-password"
    # Old password still works.
    login_csrf = _csrf(client.get("/login").text)
    good = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert good.headers["location"] == "/vault"


def test_forgot_password_rejects_password_without_complexity(client):
    """Recovery refuses to set a master password that fails complexity rules."""
    _login(client)
    client.cookies.clear()
    forgot_csrf = _csrf(client.get("/forgot-password").text)
    look = client.post(
        "/forgot-password",
        data={"username": "alice", "_csrf": forgot_csrf},
        follow_redirects=False,
    )
    page_csrf = _csrf(look.text)
    r = client.post(
        "/forgot-password/recover",
        data={
            "_csrf": page_csrf,
            "username": "alice",
            "answer1": "Fluffy",
            "answer2": "Boston",
            # 12+ chars but no uppercase / symbol → must be rejected even with
            # correct answers.
            "new_password": "alllowercaseonly",
            "confirm_password": "alllowercaseonly",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/forgot-password"
    # Old password still works — recovery did not silently overwrite it.
    login_csrf = _csrf(client.get("/login").text)
    good = client.post(
        "/login",
        data={"username": "alice", "master_password": "Correct!horse1", "_csrf": login_csrf},
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert good.headers["location"] == "/vault"
