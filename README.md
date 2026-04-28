# KeyMasters-MasterKey

Self-hosted password manager. USM Course CSC 327 Final Project — Team KeyMasters (Bibas, Abhishek, Nathaniel, Javokhir).

Store and retrieve credentials behind a master password. All credential fields are encrypted with AES-256-GCM before reaching the database — a stolen database file exposes no plaintext passwords, usernames, or service names without the master password.

## Requirements

- Python 3.10 or newer
- pip

## Setup

```bash
python -m venv venv
```

Activate the virtual environment:

| Platform | Command |
|---|---|
| macOS / Linux | `source venv/bin/activate` |
| Windows (PowerShell / Git Bash) | `venv/Scripts/activate` |
| Windows (cmd.exe) | `venv\Scripts\activate.bat` |

Then install dependencies and copy the config file:

```bash
pip install -r requirements.txt
```

**macOS / Linux**
```bash
cp .env.example .env
```

**Windows**
```powershell
copy .env.example .env
```

Then generate a secret key and write it into `.env`:

**macOS / Linux**
```bash
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))" >> .env
```

**Windows (PowerShell)**
```powershell
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))" | Add-Content .env
```

## Running

```bash
uvicorn app.main:create_app --factory --reload
```

Then open **http://127.0.0.1:8000** in your browser to use the app.

API docs (Swagger UI): http://127.0.0.1:8000/docs

## Testing

```bash
pytest                                                      # all tests
pytest tests/test_auth_routes.py::test_login_happy_path -v  # single test
pytest --cov=app --cov-report=term-missing                  # coverage
```

## Demo

1. Run the app and open http://127.0.0.1:8000
2. Click **Create a Vault** and create an account with a strong master password
3. Add a credential — the service name, username, and password are encrypted before storage
4. To verify: open `master_key.sqlite` with any SQLite viewer — all credential fields (service, username, password, notes) are stored as encrypted blobs, not plaintext

We do not provide pre-built test accounts or a seed database. This is intentional. A pre-seeded database would contain bcrypt hashes tied to a known password, which could be cracked offline — contradicting the security model we are demonstrating. Storing credentials in the repo, even hashed, treats the project as if it were a normal app rather than a security-critical one. Creating your own account takes under a minute and produces a database that is genuinely encrypted with a key only you hold, which is the correct demonstration of the system.

## Stack

FastAPI · SQLite · bcrypt · PBKDF2 · JWT (HS256) · AES-256-GCM
