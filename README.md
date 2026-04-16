# KeyMasters-MasterKey

Self-hosted password manager. Course 327 final project — team KeyMasters (Bibas, Abhishek, Nathaniel, Javokhir).

## Quickstart

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit JWT_SECRET
uvicorn app.main:create_app --factory --reload
```

API docs: `http://127.0.0.1:8000/docs`

## Testing

```bash
pytest                                                      # all tests
pytest tests/test_auth_routes.py::test_login_happy_path -v  # single test
pytest --cov=app --cov-report=term-missing                  # coverage
```

## Stack

FastAPI · SQLite · bcrypt · PBKDF2 · JWT (HS256) · Fernet (AES-256)

See project docs for architecture, security invariants, and team interfaces.
