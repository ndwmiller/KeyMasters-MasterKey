from tests.conftest import register_payload


def test_full_user_journey(client):
    client.post("/auth/register", json=register_payload())
    token = client.post(
        "/auth/login",
        json={"username": "alice", "master_password": "Correct!horse1"},
    ).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}

    gen = client.post("/credentials/generate", json={"length": 20}, headers=h).json()["password"]
    created = client.post(
        "/credentials",
        json={
            "service": "gmail",
            "username": "alice@x.com",
            "password": gen,
            "notes": "work account",
        },
        headers=h,
    ).json()
    cid = created["id"]

    full = client.get(f"/credentials/{cid}", headers=h).json()
    assert full["password"] == gen
    assert full["notes"] == "work account"

    client.put(f"/credentials/{cid}", json={"notes": "personal account"}, headers=h)
    assert (
        client.get(f"/credentials/{cid}", headers=h).json()["notes"] == "personal account"
    )

    client.post("/auth/logout", headers=h)
    assert client.get("/credentials", headers=h).status_code == 401
