# KeyMasters-MasterKey

Self-hosted password manager. Course 327 final project — team KeyMasters (Bibas, Abhishek, Nathaniel, Javokhir).

Store and retrieve credentials behind a master password. All data is encrypted with AES-256-GCM before it touches the database — a stolen database file is useless without the master password.

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
cp .env.example .env
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

## Stack

FastAPI · SQLite · bcrypt · PBKDF2 · JWT (HS256) · AES-256-GCM
