def test_register_happy_path(client):
    r = client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"
    assert "id" in body
    assert "master_password" not in body
    assert "bcrypt_hash" not in r.text


def test_register_duplicate_username(client):
    client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    r = client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    assert r.status_code == 409


def test_register_validation_errors(client):
    r = client.post(
        "/auth/register",
        json={"username": "", "master_password": "correct horse battery"},
    )
    assert r.status_code == 422
    r = client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "short"},
    )
    assert r.status_code == 422


def _register(client, username: str = "alice", password: str = "correct horse battery") -> None:
    r = client.post("/auth/register", json={"username": username, "master_password": password})
    assert r.status_code == 201


def test_login_happy_path(client):
    _register(client)
    r = client.post(
        "/auth/login",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str)
    assert len(body["access_token"]) > 20


def test_login_wrong_password_generic_401(client):
    _register(client)
    r = client.post(
        "/auth/login",
        json={"username": "alice", "master_password": "nope nope nope"},
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "authentication failed"}


def test_login_unknown_user_generic_401(client):
    r = client.post(
        "/auth/login",
        json={"username": "ghost", "master_password": "nope nope nope"},
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "authentication failed"}


def test_logout_clears_session(client):
    _register(client)
    token = client.post(
        "/auth/login",
        json={"username": "alice", "master_password": "correct horse battery"},
    ).json()["access_token"]
    r = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 204
