import pytest

from app.crypto.encryption import decrypt_credential, encrypt_credential


KEY = b"\x11" * 32
OTHER = b"\x22" * 32


def test_round_trip():
    ct = encrypt_credential(KEY, "hunter2")
    assert isinstance(ct, bytes)
    assert ct != b"hunter2"
    assert decrypt_credential(KEY, ct) == "hunter2"


def test_wrong_key_raises():
    ct = encrypt_credential(KEY, "hunter2")
    with pytest.raises(Exception):
        decrypt_credential(OTHER, ct)


def test_each_encrypt_is_unique():
    ct1 = encrypt_credential(KEY, "same")
    ct2 = encrypt_credential(KEY, "same")
    assert ct1 != ct2
