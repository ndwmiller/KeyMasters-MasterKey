import pytest

from app.services.password_gen import generate_password


def test_default_length():
    pw = generate_password()
    assert len(pw) == 20


def test_custom_length():
    assert len(generate_password(length=32)) == 32


def test_minimum_length_enforced():
    with pytest.raises(ValueError):
        generate_password(length=7)


def test_contains_required_classes():
    for _ in range(25):
        pw = generate_password(length=16)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in "!@#$%^&*()-_=+[]{};:,.<>/?" for c in pw)
