# KeyMasters-MasterKey

Self-hosted password manager. USM Course CSC 327 Final Project — Team KeyMasters (Bibas, Abhishek, Nathaniel, Javokhir).

Store and retrieve credentials behind a master password. Every credential field is encrypted with AES-256-GCM before reaching the database — a stolen database file exposes no plaintext passwords, usernames, or service names without the master password.

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

## Using the app

### 1 — Create your vault

1. Open http://127.0.0.1:8000 — you'll be redirected to the unlock page.
2. Click **Create a vault** at the bottom of the form.
3. Fill in:
   - **Username** — anything; only used to identify you on this device.
   - **Master password** — must be at least 12 characters and contain at least one uppercase letter, one lowercase letter, and one symbol (`!@#$%^&*()-_=+[]{};:,.<>/?`). This is the only key to your vault.
   - **Confirm master password** — same value again.
   - **Recovery question 1 + answer** — pick from the dropdown. The answer is case-insensitive and trims whitespace.
   - **Recovery question 2 + answer** — must be a different question.
4. Click **Forge Vault**. You're auto-logged-in and dropped on your empty vault.

> The master password is bcrypt-hashed before storage. The encryption key for your credentials is derived from the master password at unlock time and held only in memory — the database alone cannot decrypt anything.

### 2 — Store a credential

1. Click **Add Credential** in the sidebar (or the green button on the empty-vault screen).
2. Fill in:
   - **Service** — e.g. *github.com*, *Netflix*, *Bank of XYZ*.
   - **Username / email** — whatever you log in with on that service.
   - **Password** — paste an existing password, or click **Generate** to create a random one.
   - **Notes** *(optional)* — free-form text (e.g. recovery codes, account numbers).
3. Click **Save Credential**. Each field is AES-256-GCM-encrypted before it touches SQLite.

### 3 — Look up a credential

1. The vault list shows every saved item by service name. Click any card to open it.
2. On the detail page:
   - The **password** field is masked. Click the eye to reveal it, or the clipboard icon to copy.
   - The **username** and **notes** fields each have their own copy buttons.

### 4 — Edit or delete a credential

- On the detail page, click **Edit** to change any field, then **Save Changes**.
- Click **Delete** on the detail page to remove a credential. You'll be asked to confirm.

### 5 — Lock the vault

- Click the unlock icon in the top-right of any page (or **Lock Vault Now** in Settings).
- Locking drops your in-memory encryption key. To get back in, you'll need your master password.
- Sessions also auto-expire after 15 minutes of activity (configurable via `SESSION_TTL_MINUTES`).

### 6 — Change your master password

1. Open **Settings** in the sidebar (icon: ⚙).
2. Expand **Change Master Password**.
3. Enter your current password, your new password (same complexity rules), and confirm.
4. Click **Update Password**. Your stored credentials are *not* re-encrypted — only the wrapping of the encryption key changes — so this is fast and lossless.

### 7 — Update your recovery questions

1. In **Settings**, expand **Recovery Questions**.
2. Enter your current master password, then pick two questions and provide answers.
3. Click **Save Recovery Questions**.

### 8 — Forgot your master password?

1. From the unlock page, click **Recover with security questions**.
2. Enter your username and click **Continue**.
3. Answer both of your security questions and choose a new master password (same complexity rules).
4. Click **Reset Master Password** and log back in with the new password — your existing credentials are still readable, untouched.

> Recovery is gated by your two security-question answers being correct as a unit. Wrong answers fail the unwrap and leave the vault unchanged.

### 9 — Delete your account

1. In **Settings**, scroll to the **Danger Zone**.
2. Type your username for confirmation, enter your master password, and click **Delete Account Permanently**.
3. Your user row and every encrypted credential row are removed (cascade delete). There is no undo.

## Testing

```bash
pytest                                                      # all tests
pytest tests/test_auth_routes.py::test_login_happy_path -v  # single test
pytest --cov=app --cov-report=term-missing                  # coverage
```

## Demo / presentation

`presentation.html` is a 12-slide deck for the project demo. Slides 7–9 are live attack/defense demos (rate-limit brute force, DB-theft attempt, CSRF rejection); each terminal block has a copy button.

To run the demos:

```bash
# Terminal 1 — start the server from the repo root and leave it running
.venv/bin/uvicorn --factory app.main:create_app --port 8000

# Terminal 2 — seed alice + a credential (once)
bash demo/seed.sh
bash demo/login.sh   # only needed before the CSRF slide
```

Then either click the slide's Copy button and paste, or run the equivalent `demo/01-bruteforce.sh`, `demo/02-dbtheft.sh`, `demo/03-csrf.sh`.

We do **not** ship a pre-seeded database. A seeded DB would contain bcrypt hashes tied to a known password, which could be cracked offline — contradicting the security model we are demonstrating. Creating your own vault takes under a minute and produces a database genuinely encrypted with a key only you hold.

## Stack

FastAPI · SQLite · bcrypt · PBKDF2 · JWT (HS256) · AES-256-GCM
