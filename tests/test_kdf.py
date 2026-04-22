from app.auth.kdf import derive_key, new_salt


def test_salt_is_16_bytes_and_random():
    s1 = new_salt()
    s2 = new_salt()
    assert len(s1) == 16
    assert s1 != s2


def test_derive_key_returns_32_bytes():
    key = derive_key("password123456", b"\x00" * 16)
    assert len(key) == 32
    assert isinstance(key, bytes)


def test_derive_key_is_deterministic():
    salt = b"\x01" * 16
    assert derive_key("pw", salt) == derive_key("pw", salt)


def test_derive_key_differs_by_salt():
    assert derive_key("pw", b"\x01" * 16) != derive_key("pw", b"\x02" * 16)


def test_derive_key_differs_by_password():
    salt = b"\x01" * 16
    assert derive_key("pw1", salt) != derive_key("pw2", salt)
