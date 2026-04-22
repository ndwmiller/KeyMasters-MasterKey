from app.auth.password import hash_master_password, verify_master_password


def test_hash_is_not_plaintext():
    h = hash_master_password("correct horse battery staple")
    assert h != b"correct horse battery staple"
    assert h.startswith(b"$2b$")


def test_verify_correct_password():
    h = hash_master_password("correct horse battery staple")
    assert verify_master_password("correct horse battery staple", h) is True


def test_verify_wrong_password():
    h = hash_master_password("correct horse battery staple")
    assert verify_master_password("wrong", h) is False


def test_hashes_are_unique_per_call():
    h1 = hash_master_password("same password")
    h2 = hash_master_password("same password")
    assert h1 != h2
