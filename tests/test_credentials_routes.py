def _auth_headers(client, username: str = "alice") -> dict[str, str]:
    client.post(
        "/auth/register",
        json={"username": username, "master_password": "Correct!horse1"},
    )
    token = client.post(
        "/auth/login",
        json={"username": username, "master_password": "Correct!horse1"},
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_unauthenticated_endpoints_401(client):
    paths: list[tuple[str, str, dict | None]] = [
        ("get", "/credentials", None),
        ("post", "/credentials", {"service": "x", "username": "u", "password": "p"}),
        ("get", "/credentials/1", None),
        ("put", "/credentials/1", {"service": "x"}),
        ("delete", "/credentials/1", None),
        ("post", "/credentials/generate", {"length": 16}),
    ]
    for method, path, body in paths:
        kwargs = {"json": body} if body is not None else {}
        r = getattr(client, method)(path, **kwargs)
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"


def test_create_list_get_update_delete(client):
    h = _auth_headers(client)
    r = client.post(
        "/credentials",
        json={"service": "github", "username": "alice", "password": "hunter2"},
        headers=h,
    )
    assert r.status_code == 201
    cid = r.json()["id"]

    listed = client.get("/credentials", headers=h).json()
    assert len(listed) == 1
    assert listed[0]["service"] == "github"
    assert "password" not in listed[0]

    full = client.get(f"/credentials/{cid}", headers=h).json()
    assert full["password"] == "hunter2"
    assert full["username"] == "alice"

    updated = client.put(
        f"/credentials/{cid}", json={"password": "hunter3"}, headers=h
    ).json()
    assert updated["password"] == "hunter3"
    assert updated["service"] == "github"

    r = client.delete(f"/credentials/{cid}", headers=h)
    assert r.status_code == 204
    assert client.get("/credentials", headers=h).json() == []


def test_cannot_access_other_users_credential(client):
    h_a = _auth_headers(client, username="alice")
    cid = client.post(
        "/credentials",
        json={"service": "github", "username": "u", "password": "p"},
        headers=h_a,
    ).json()["id"]

    h_b = _auth_headers(client, username="bob")

    assert client.get(f"/credentials/{cid}", headers=h_b).status_code == 404
    assert client.put(f"/credentials/{cid}", json={"service": "x"}, headers=h_b).status_code == 404
    assert client.delete(f"/credentials/{cid}", headers=h_b).status_code == 404


def test_generate_returns_strong_password(client):
    h = _auth_headers(client)
    r = client.post("/credentials/generate", json={"length": 24}, headers=h)
    assert r.status_code == 200
    pw = r.json()["password"]
    assert len(pw) == 24
