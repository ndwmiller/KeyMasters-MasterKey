from app.web.csrf import issue_token, validate

SECRET = "x" * 32


def test_issued_token_validates():
    t = issue_token(SECRET)
    assert validate(SECRET, t, t) is True


def test_mismatch_fails():
    a = issue_token(SECRET)
    b = issue_token(SECRET)
    assert validate(SECRET, a, b) is False


def test_missing_sides_fail():
    t = issue_token(SECRET)
    assert validate(SECRET, None, t) is False
    assert validate(SECRET, t, None) is False
    assert validate(SECRET, None, None) is False


def test_forged_signature_fails():
    assert validate(SECRET, "not-a-real-token", "not-a-real-token") is False


def test_wrong_secret_fails():
    t = issue_token(SECRET)
    assert validate("y" * 32, t, t) is False
