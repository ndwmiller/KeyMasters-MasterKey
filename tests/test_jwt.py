from datetime import timedelta

import pytest

from app.auth.jwt import JWTError, decode_token, issue_token


SECRET = "x" * 32


def test_issue_and_decode_round_trip():
    token = issue_token({"sub": "42", "sid": "abc"}, SECRET)
    claims = decode_token(token, SECRET)
    assert claims["sub"] == "42"
    assert claims["sid"] == "abc"
    assert "exp" in claims


def test_expired_token_rejected():
    token = issue_token({"sub": "42"}, SECRET, ttl=timedelta(seconds=-1))
    with pytest.raises(JWTError):
        decode_token(token, SECRET)


def test_wrong_secret_rejected():
    token = issue_token({"sub": "42"}, SECRET)
    with pytest.raises(JWTError):
        decode_token(token, "y" * 32)


def test_tampered_token_rejected():
    token = issue_token({"sub": "42"}, SECRET)
    bad = token[:-4] + "aaaa"
    with pytest.raises(JWTError):
        decode_token(bad, SECRET)
