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
