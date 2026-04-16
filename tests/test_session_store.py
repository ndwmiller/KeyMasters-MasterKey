import time

from app.auth.session_store import SessionStore


def test_create_and_get_round_trip():
    s = SessionStore(ttl_seconds=60)
    sid = s.create(user_id=1, key=b"\x00" * 32)
    assert s.get(sid) == (1, b"\x00" * 32)


def test_get_unknown_sid_returns_none():
    s = SessionStore(ttl_seconds=60)
    assert s.get("nope") is None


def test_expired_session_returns_none():
    s = SessionStore(ttl_seconds=0)
    sid = s.create(user_id=1, key=b"\x00" * 32)
    time.sleep(0.01)
    assert s.get(sid) is None


def test_delete_removes_session():
    s = SessionStore(ttl_seconds=60)
    sid = s.create(user_id=1, key=b"\x00" * 32)
    s.delete(sid)
    assert s.get(sid) is None


def test_sids_are_unique_and_opaque():
    s = SessionStore(ttl_seconds=60)
    sids = {s.create(user_id=i, key=b"\x00" * 32) for i in range(100)}
    assert len(sids) == 100
    for sid in sids:
        assert len(sid) >= 32
