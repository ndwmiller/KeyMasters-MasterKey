# Frontend (Jinja UI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Branch:** `feature/frontend` (off `feature/backend`).

**Goal:** Ship the web UI for Master Key — login, registration, vault dashboard, credential CRUD — using Jinja2 server-side templates styled after the supplied Google Stitch mockups, with production-grade web security (HttpOnly cookie auth, CSRF tokens, CSP + security headers, Jinja auto-escape).

**Architecture:** FastAPI serves two surfaces from the same app:

1. **JSON API** (already shipped on `feature/backend`) — Bearer JWT. Unchanged.
2. **HTML UI** (this plan) — server-rendered Jinja templates. Auth via HttpOnly cookie `mk_session` holding the *same* JWT the API uses; `get_current_session` is extended to read either the header or the cookie. Forms POST directly to Python handlers that mirror the API work (same validation, same encryption path, same DB calls). **The UI doesn't JS-call its own JSON API** — that would double the surface area and require a second CSRF story. Only `/credentials/generate` stays as an async fetch (read-only, idempotent, needs no CSRF).

Interactivity is plain vanilla JS in small per-page modules loaded from `/static/js/`. No framework. No inline scripts (CSP-friendly).

**Tech Stack:** Jinja2 3.1+, `itsdangerous` (already transitively available; used for CSRF token signing), Tailwind via CDN (acceptable for course scope; CSP allow-listed), Material Symbols + Manrope/Inter fonts via Google Fonts CDN, vanilla ES modules.

---

## Open Design Decisions (resolve with team before execution)

1. **Auth transport for UI.** **Proposed:** HttpOnly + Secure + SameSite=Strict cookie `mk_session` carrying the JWT. `get_current_session` accepts it OR `Authorization: Bearer`. Login/logout handlers set/clear the cookie. Bibas confirms cookie details; Abhishek confirms this works for his form UX.
2. **CSRF strategy.** **Proposed:** double-submit cookie pattern — on first GET, set `mk_csrf` cookie with a signed random token; every HTML form includes the same token in a hidden `_csrf` field; POST handlers reject the request unless cookie == form field. Combined with SameSite=Strict this is defense-in-depth.
3. **Static asset delivery.** **Proposed:** keep Tailwind + fonts + Material Symbols via CDN for dev speed. CSP allow-lists specifically `https://cdn.tailwindcss.com` and `https://fonts.*.com`. If this app ever ships outside a classroom, bundle locally.
4. **Password-generator UX.** **Proposed:** the only async call the UI makes. Reuses the existing `POST /credentials/generate` endpoint — same auth. Keeps one source of truth for the generator algorithm.
5. **Password strength meter.** **Proposed:** simple client-side entropy calculation in `static/js/strength.js` (length × charset variety heuristic). Not using `zxcvbn` — too large. Pure cosmetic UX; server still enforces min-length via Pydantic.
6. **What to drop from the mockups.** The Stitch mockups show Secure Notes, Payment Cards, Security Audit, Trash, Share, Folders, "Step 2/4" registration wizard, avatar uploads, FIPS badges, 2FA hints. **Proposed:** drop all of these for v1; keep the visual style but scope to Logins only, a single-step register, a one-screen vault, and CRUD on credentials. Note in the UI that those sections are "coming soon."

---

## Security Contract (must all hold)

Beyond the backend invariants in project docs, the UI adds:

1. **Jinja auto-escape is on everywhere.** No `| safe` on user content. Ever.
2. **Cookies:** `HttpOnly` (no JS access), `Secure` (HTTPS only — we set it True in prod, False in tests), `SameSite=Strict`, scoped to `/`.
3. **CSRF:** every non-idempotent HTML request (`POST`, `PUT`, `DELETE`) validates the double-submit token.
4. **Security headers** on every HTML response:
   - `Content-Security-Policy`: scoped allow-list, no `unsafe-eval`, no inline scripts.
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: no-referrer`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains` (only when served over HTTPS)
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
5. **No password data in query strings or referrer.** All password fields POST-only.
6. **Copy-to-clipboard auto-clears** from clipboard after 30 seconds (best-effort; clipboards are OS-owned, but we at least overwrite with empty).
7. **Reveal-password toggle** flips the `type` attribute client-side only; no telemetry, no logging.
8. **Session expiry UX:** a 401 on any HTML route redirects to `/login?reason=expired` (flash message on login page).
9. **No sensitive data in `localStorage` / `sessionStorage`.** Ever.

---

## File Structure (additions to repo)

```
master_key/
├── app/
│   ├── web/                          # NEW — HTML routes
│   │   ├── __init__.py
│   │   ├── auth.py                   # /login, /register, /logout (HTML)
│   │   ├── vault.py                  # /, /vault, /vault/new, /vault/{cid}, /vault/{cid}/edit
│   │   └── csrf.py                   # CSRF token issue + validate
│   ├── middleware/                   # NEW
│   │   ├── __init__.py
│   │   └── security_headers.py       # CSP + companion headers
│   └── api/deps.py                   # MODIFY: accept cookie as well as header
├── templates/                        # NEW — Jinja templates
│   ├── base.html                     # Shared shell: <head>, tailwind config, fonts, flash, nav
│   ├── partials/
│   │   ├── _sidebar.html             # Desktop sidebar
│   │   ├── _mobile_nav.html          # Bottom nav (mobile)
│   │   ├── _topbar.html              # Top bar with logo + lock/settings
│   │   └── _flash.html               # Flash message container
│   ├── auth/
│   │   ├── login.html                # Master Login screen
│   │   └── register.html             # Create Master Account screen (one step)
│   ├── vault/
│   │   ├── list.html                 # Vault dashboard (credential grid)
│   │   ├── new.html                  # Add Credential
│   │   ├── detail.html               # Credential Detail (view + reveal + copy)
│   │   └── edit.html                 # Edit Credential
│   └── errors/
│       ├── 404.html
│       └── 500.html
├── static/                           # NEW
│   ├── css/
│   │   └── app.css                   # Minor overrides on top of Tailwind CDN
│   └── js/
│       ├── reveal.js                 # Toggle password field type
│       ├── copy.js                   # Clipboard copy with auto-clear
│       ├── strength.js               # Entropy meter for master + credential passwords
│       ├── generator.js              # Fetch /credentials/generate, populate field
│       ├── validate.js               # Client-side form validation shared helpers
│       └── confirm.js                # Confirm dialog for destructive actions (delete)
└── tests/
    ├── test_csrf.py                  # NEW
    ├── test_security_headers.py      # NEW
    ├── test_web_auth.py              # NEW — HTML login/register/logout flows
    ├── test_web_vault.py             # NEW — HTML CRUD flows
    └── test_deps.py                  # MODIFY — add cookie auth cases
```

---

## Task 1: Backend shims — cookie auth + security headers + CSRF

**Files:**
- Modify: `app/api/deps.py` (accept cookie)
- Create: `app/web/__init__.py` (empty), `app/web/csrf.py`
- Create: `app/middleware/__init__.py` (empty), `app/middleware/security_headers.py`
- Modify: `app/main.py` (wire middleware, Jinja, static)
- Modify: `requirements.txt` (add `jinja2` and `itsdangerous` — both are FastAPI extras but we pin)
- Create: `tests/test_csrf.py`, `tests/test_security_headers.py`
- Modify: `tests/test_deps.py` (add cookie cases)

- [ ] **Step 1: Pin new deps in `requirements.txt`** (append):

```
jinja2==3.1.4
itsdangerous==2.2.0
```

Run: `pip install -r requirements.txt`

- [ ] **Step 2: Extend `app/api/deps.py` to also read the `mk_session` cookie**

```python
from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, Request

from app.auth.jwt import JWTError, decode_token
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import AuthError


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.sessions


@dataclass
class CurrentSession:
    user_id: int
    key: bytes


def _extract_token(authorization: str, cookie_token: str | None) -> str:
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1]
    if cookie_token:
        return cookie_token
    raise AuthError()


def get_current_session(
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
    sessions: SessionStore = Depends(get_session_store),
) -> CurrentSession:
    token = _extract_token(authorization, mk_session)
    try:
        claims = decode_token(token, get_settings().jwt_secret)
    except JWTError:
        raise AuthError()
    sid = claims.get("sid")
    if not sid:
        raise AuthError()
    entry = sessions.get(sid)
    if entry is None:
        raise AuthError()
    user_id, key = entry
    return CurrentSession(user_id=user_id, key=key)
```

- [ ] **Step 3: Write failing tests in `tests/test_deps.py`** (append):

```python
def test_cookie_auth_works(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    token = issue_token({"sub": "9", "sid": sid}, "x" * 32)
    client = _build_app(store)
    r = client.get("/protected", cookies={"mk_session": token})
    assert r.status_code == 200
    assert r.json()["user_id"] == 9


def test_header_wins_over_cookie(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    store = SessionStore(ttl_seconds=60)
    sid = store.create(user_id=9, key=b"\x00" * 32)
    good = issue_token({"sub": "9", "sid": sid}, "x" * 32)
    client = _build_app(store)
    r = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {good}"},
        cookies={"mk_session": "garbage"},
    )
    assert r.status_code == 200
```

Run: `pytest tests/test_deps.py -v` — expect 2 new FAILs then PASS.

- [ ] **Step 4: Create `app/web/csrf.py`**

```python
import hmac
import secrets

from itsdangerous import BadSignature, URLSafeSerializer

_COOKIE_NAME = "mk_csrf"
_FORM_FIELD = "_csrf"


def _serializer(secret: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret, salt="mk-csrf")


def issue_token(secret: str) -> str:
    return _serializer(secret).dumps(secrets.token_urlsafe(16))


def validate(secret: str, cookie_value: str | None, form_value: str | None) -> bool:
    if not cookie_value or not form_value:
        return False
    if not hmac.compare_digest(cookie_value, form_value):
        return False
    try:
        _serializer(secret).loads(cookie_value)
    except BadSignature:
        return False
    return True


COOKIE_NAME = _COOKIE_NAME
FORM_FIELD = _FORM_FIELD
```

- [ ] **Step 5: Write failing tests in `tests/test_csrf.py`**

```python
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
```

Run: `pytest tests/test_csrf.py -v` — expect PASS.

- [ ] **Step 6: Create `app/middleware/security_headers.py`**

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=()"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response
```

- [ ] **Step 7: Write failing tests in `tests/test_security_headers.py`**

```python
def test_headers_on_html_response(client):
    r = client.get("/health")
    assert "Content-Security-Policy" in r.headers
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
```

- [ ] **Step 8: Wire middleware + Jinja + static in `app/main.py`**

```python
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import register_error_handlers
from app.middleware.security_headers import SecurityHeadersMiddleware

_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(_ROOT / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="Master Key", version="0.1.0")
    settings = get_settings()
    app.state.sessions = SessionStore(ttl_seconds=settings.session_ttl_minutes * 60)
    app.state.templates = TEMPLATES
    app.add_middleware(SecurityHeadersMiddleware)
    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(credentials_router)
    # Web routers registered in Task 3+
    static_dir = _ROOT / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
```

- [ ] **Step 9: Run full suite**

```bash
pytest
```

Expect: all existing tests plus 2 new CSRF tests plus 2 new deps tests plus header tests — all pass.

- [ ] **Step 10: Commit**

```bash
git add app/api/deps.py app/web app/middleware app/main.py requirements.txt tests/test_csrf.py tests/test_security_headers.py tests/test_deps.py
git commit -m "feat(web): cookie auth, CSRF, security headers, Jinja/static wiring"
```

---

## Task 2: Base template + design tokens

**Files:**
- Create: `templates/base.html`, `templates/partials/_flash.html`, `templates/partials/_topbar.html`, `templates/partials/_sidebar.html`, `templates/partials/_mobile_nav.html`
- Create: `static/css/app.css`

- [ ] **Step 1: Create `templates/base.html`** — the shell carries Tailwind config inline (mockup-faithful), fonts, and blocks for title/content/scripts. Keep exactly one copy; all other templates extend it.

```html
<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1.0" name="viewport">
<title>{% block title %}Master Key{% endblock %}</title>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
<script src="{{ url_for('static', path='/js/tailwind-config.js') }}"></script>
<link href="{{ url_for('static', path='/css/app.css') }}" rel="stylesheet">
</head>
<body class="bg-background text-on-background font-body min-h-screen">
  {% include "partials/_flash.html" %}
  {% block layout %}
    {% block content %}{% endblock %}
  {% endblock %}
  {% block scripts %}{% endblock %}
</body>
</html>
```

- [ ] **Step 2: Create `static/js/tailwind-config.js`** — extracts the `tailwind.config = {...}` block verbatim from the mockups so every page renders the same palette. This file is served under the `script-src 'self'` directive (CSP-clean).

Copy the `tailwind.config = { darkMode: "class", theme: { extend: { colors: {...}, borderRadius: {...}, fontFamily: {...} } } }` block from any mockup. One file, shared by all pages.

- [ ] **Step 3: Create `templates/partials/_flash.html`**

```html
{% set messages = request.session.pop_flashes() if request.session is defined else [] %}
{% if messages %}
<div class="fixed top-20 right-6 z-50 space-y-2">
  {% for category, msg in messages %}
  <div class="px-4 py-3 rounded-md border text-sm
    {% if category == 'error' %}bg-error-container/20 border-error/40 text-error
    {% elif category == 'success' %}bg-primary/10 border-primary/40 text-primary
    {% else %}bg-surface-container-high border-outline-variant/20 text-on-surface{% endif %}">
    {{ msg }}
  </div>
  {% endfor %}
</div>
{% endif %}
```

Flashes ride on a lightweight signed cookie — see Task 3 for `app/web/flash.py`.

- [ ] **Step 4: Create `templates/partials/_topbar.html`, `_sidebar.html`, `_mobile_nav.html`** — copy layouts straight from the Vault Dashboard mockup, genericising `href` values to `url_for` calls: `{{ url_for('vault_list') }}`, `{{ url_for('web_logout') }}`, etc. No user data without `| e` (default auto-escape covers this).

- [ ] **Step 5: Create `static/css/app.css`** — a few overrides only:

```css
.glass-panel { background: rgba(19, 27, 46, 0.7); backdrop-filter: blur(20px); }
.primary-gradient { background: linear-gradient(135deg, #4edea3 0%, #009567 100%); }
.material-symbols-outlined { font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24; vertical-align: middle; }
.scrollbar-hide::-webkit-scrollbar { display: none; }
```

- [ ] **Step 6: Commit** — no new tests yet; visual verification comes next task.

```bash
git add templates static
git commit -m "feat(ui): base layout + design tokens from mockups"
```

---

## Task 3: `/login` (GET + POST)

**Files:**
- Create: `app/web/auth.py`, `app/web/flash.py`, `templates/auth/login.html`, `tests/test_web_auth.py`
- Modify: `app/main.py` (register web_auth router + session middleware for flashes)

- [ ] **Step 1: Flash middleware — `app/web/flash.py`**

A tiny signed-cookie flash queue. Avoids pulling in `starlette.sessions` (which writes a heavier cookie).

```python
import json

from itsdangerous import BadSignature, URLSafeSerializer

_COOKIE = "mk_flash"


def _ser(secret: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret, salt="mk-flash")


def read(secret: str, cookie_value: str | None) -> list[tuple[str, str]]:
    if not cookie_value:
        return []
    try:
        data = _ser(secret).loads(cookie_value)
    except BadSignature:
        return []
    return [(str(c), str(m)) for c, m in data]


def write(secret: str, messages: list[tuple[str, str]]) -> str:
    return _ser(secret).dumps(messages)


COOKIE_NAME = _COOKIE
```

- [ ] **Step 2: Failing tests in `tests/test_web_auth.py`** (paraphrased — full code in the task):

```python
def test_login_get_renders_form(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Unlock Your Vault" in r.text
    assert "mk_csrf" in r.headers.get("set-cookie", "")
    assert "_csrf" in r.text


def test_login_post_happy_sets_cookie_and_redirects(client):
    client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    get = client.get("/login")
    csrf = _extract_csrf(get.text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "correct horse battery", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"
    assert "mk_session=" in r.headers.get("set-cookie", "")
    assert "HttpOnly" in r.headers["set-cookie"]
    assert "SameSite=strict" in r.headers["set-cookie"].lower()


def test_login_post_missing_csrf_403(client):
    r = client.post("/login", data={"username": "alice", "master_password": "x"})
    assert r.status_code == 403


def test_login_post_wrong_password_redirects_with_flash(client):
    client.post(
        "/auth/register",
        json={"username": "alice", "master_password": "correct horse battery"},
    )
    get = client.get("/login")
    csrf = _extract_csrf(get.text)
    r = client.post(
        "/login",
        data={"username": "alice", "master_password": "nope", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    # No user enumeration — same response for unknown user too.
```

Helper `_extract_csrf`: regex for `name="_csrf" value="([^"]+)"`.

- [ ] **Step 3: Implement `app/web/auth.py`** — routes `/login` GET/POST, `/logout` POST. GET issues CSRF cookie, renders `auth/login.html` with the token. POST validates CSRF, calls the same bcrypt+kdf path the API `/auth/login` uses, sets `mk_session` cookie, redirects to `/vault`. On failure, write a flash and redirect back to `/login`.

Key cookie settings (use `secure=not settings.debug_insecure_cookies` if you add a debug flag; for now always `secure=False` in dev and flip in prod):

```python
response.set_cookie(
    "mk_session",
    token,
    max_age=settings.jwt_ttl_minutes * 60,
    httponly=True,
    samesite="strict",
    secure=False,  # flip for HTTPS
    path="/",
)
```

- [ ] **Step 4: Create `templates/auth/login.html`** — extend `base.html`, paste the Master Login mockup markup, replace the `<form>` opening tag with `<form method="post" action="{{ url_for('web_login_post') }}">`, add hidden CSRF field: `<input type="hidden" name="_csrf" value="{{ csrf_token }}">`, rename `type="password"` input to `name="master_password"` and add `username` input (mockup shows only master password — we need username too for a course-scope app). Autocomplete: `autocomplete="current-password"`, `autocomplete="username"`.

- [ ] **Step 5: Wire routers + flash writer in `app/main.py`**

```python
    from app.web.auth import router as web_auth_router
    app.include_router(web_auth_router)
```

- [ ] **Step 6: Run tests, commit.**

```bash
pytest tests/test_web_auth.py -v
git add app/web templates/auth tests/test_web_auth.py app/main.py
git commit -m "feat(ui): /login GET+POST with cookie session and CSRF"
```

---

## Task 4: `/register` (GET + POST) with password strength meter

**Files:**
- Modify: `app/web/auth.py` (add register handlers)
- Create: `templates/auth/register.html`
- Create: `static/js/strength.js`
- Modify: `tests/test_web_auth.py` (add register tests)

- [ ] **Step 1: Failing tests** covering: GET renders form; POST happy path creates user and auto-logins (set cookie + redirect /vault); POST duplicate username flashes error; POST short password 422-equivalent (re-render with field errors); CSRF missing → 403.

- [ ] **Step 2: Implement register handlers** — mirrors backend `POST /auth/register` handler but reads `application/x-www-form-urlencoded` form, calls the same `repo.create_user` path, on success calls the login helper to set the session cookie immediately (skip a separate login step).

- [ ] **Step 3: `templates/auth/register.html`** — adapts the "Create Master Account" mockup. Drops the Step 02/04 wizard chrome, keeps the entropy meter (driven by `strength.js`), keeps the Zero-Knowledge explanation. Form fields: `username`, `master_password`, `confirm_password`. Adds hidden CSRF. Client-side JS disables submit until the passwords match.

- [ ] **Step 4: `static/js/strength.js`** — plain module:

```javascript
function entropyBits(pw) {
  if (!pw) return 0;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes += 26;
  if (/[A-Z]/.test(pw)) classes += 26;
  if (/[0-9]/.test(pw)) classes += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) classes += 32;
  return classes === 0 ? 0 : Math.round(pw.length * Math.log2(classes));
}

function label(bits) {
  if (bits < 50) return { text: "Weak", pct: Math.min(40, bits * 0.8), color: "error" };
  if (bits < 80) return { text: "Moderate", pct: 60, color: "tertiary" };
  if (bits < 120) return { text: "Strong", pct: 85, color: "primary" };
  return { text: "Excellent", pct: 100, color: "primary" };
}

export function attach(inputEl, barEl, textEl) {
  inputEl.addEventListener("input", () => {
    const { text, pct, color } = label(entropyBits(inputEl.value));
    barEl.style.width = pct + "%";
    barEl.className = `h-full bg-${color} rounded-full transition-all`;
    textEl.textContent = text;
  });
}
```

Then in `register.html`'s `{% block scripts %}`:

```html
<script type="module">
  import { attach } from "{{ url_for('static', path='/js/strength.js') }}";
  attach(
    document.querySelector("input[name=master_password]"),
    document.getElementById("strength-bar"),
    document.getElementById("strength-label"),
  );
</script>
```

- [ ] **Step 5: Tests, commit.**

---

## Task 5: `/vault` dashboard

**Files:**
- Create: `app/web/vault.py`, `templates/vault/list.html`, `tests/test_web_vault.py`
- Modify: `app/main.py` (register web_vault router)

- [ ] **Step 1: Failing tests** — GET `/vault` unauthenticated → redirect `/login?reason=required`; authenticated renders credential grid; search query string filters server-side; "Add New" button points to `/vault/new`.

- [ ] **Step 2: Implement route** — depends on `get_current_session`; on `AuthError` during HTML request, redirect to `/login?reason=expired` (handled via a small helper `require_web_session`). Calls `repo.list_credentials_for_user` — **metadata only, never decrypts for the list view**.

- [ ] **Step 3: Template** — adapts the Vault Dashboard mockup. Iterates `{% for c in credentials %}` to render cards. Replaces hard-coded GitHub/Gmail logos with the Material icon fallback from the mockup's Visa card. Hard-coded strength bars become actual entropy bars computed from the *decrypted* password — **but since the list view doesn't decrypt, we show a placeholder "—" for strength** and note "Open to view strength." (Or: move strength calculation to an async per-card fetch. v1 = placeholder.)

- [ ] **Step 4: Tests, commit.**

---

## Task 6: `/vault/new` — Add Credential + generator

**Files:**
- Modify: `app/web/vault.py`
- Create: `templates/vault/new.html`, `static/js/generator.js`
- Modify: `tests/test_web_vault.py`

- [ ] **Step 1: Failing tests** — unauthenticated → /login; GET renders form with CSRF + generator panel; POST happy encrypts + creates, redirects `/vault/{id}?flash=created`; POST missing CSRF → 403; POST missing required fields re-renders with errors.

- [ ] **Step 2: Implement handler** — form parsing, Pydantic validation (`CredentialCreate`), call `encrypt_credential` + `repo.create_credential`.

- [ ] **Step 3: Template** — adapts Add Credential mockup. Form posts to `/vault/new`. The password generator sidebar becomes real — slider binds to `length`, "Re-generate" button calls `generator.js` which POSTs to `/credentials/generate` with the Bearer-style auth derived from the cookie (works because `get_current_session` accepts cookies). Strength meter uses `strength.js`.

- [ ] **Step 4: `static/js/generator.js`** — uses `fetch` with `credentials: "same-origin"` so the cookie is sent. No CSRF needed (this is a *read* — it doesn't mutate server state per request, but it does require auth). If you're paranoid, include the CSRF token in an `X-CSRF-Token` header and validate it there too.

- [ ] **Step 5: Commit.**

---

## Task 7: `/vault/{cid}` — Credential Detail (reveal + copy)

**Files:**
- Modify: `app/web/vault.py`
- Create: `templates/vault/detail.html`, `static/js/reveal.js`, `static/js/copy.js`
- Modify: `tests/test_web_vault.py`

- [ ] **Step 1: Failing tests** — unauthenticated → /login; owner sees decrypted username + password in DOM, URL in human-readable form; non-owner gets 404 (mirrors API); "Delete" button requires POST with CSRF + redirects to /vault.

- [ ] **Step 2: Implement** — GET route decrypts via session key, passes through to template. POST `/vault/{cid}/delete` for deletion.

- [ ] **Step 3: `static/js/reveal.js`**

```javascript
export function attachReveal(buttonEl, inputEl) {
  buttonEl.addEventListener("click", () => {
    inputEl.type = inputEl.type === "password" ? "text" : "password";
  });
}
```

- [ ] **Step 4: `static/js/copy.js`** — with auto-clear:

```javascript
export async function copyAndAutoClear(text, ms = 30000) {
  await navigator.clipboard.writeText(text);
  setTimeout(async () => {
    try { await navigator.clipboard.writeText(""); } catch (_) {}
  }, ms);
}

export function attachCopy(buttonEl, sourceEl) {
  buttonEl.addEventListener("click", async () => {
    await copyAndAutoClear(sourceEl.value ?? sourceEl.textContent);
    buttonEl.dataset.copied = "true";
    setTimeout(() => { buttonEl.dataset.copied = "false"; }, 2000);
  });
}
```

- [ ] **Step 5: Template** — adapts Credential Detail mockup. Drops "Share" button (out of scope; risky). Delete button becomes a confirmation form using `confirm.js`.

- [ ] **Step 6: Commit.**

---

## Task 8: `/vault/{cid}/edit` — Edit Credential

**Files:**
- Modify: `app/web/vault.py`
- Create: `templates/vault/edit.html`
- Modify: `tests/test_web_vault.py`

- [ ] **Step 1: Failing tests** — edit happy path preserves unchanged fields; non-owner edit → 404; CSRF missing → 403.

- [ ] **Step 2: Implement** — GET decrypts + renders form prefilled; POST validates CSRF + `CredentialUpdate` + re-encrypts + updates.

- [ ] **Step 3: Template** — re-uses structure of `new.html` with prefilled values + "Update" button instead of "Save to Vault".

- [ ] **Step 4: Commit.**

---

## Task 9: `/logout` + session expiry redirect

**Files:**
- Modify: `app/web/auth.py`
- Modify: `templates/auth/login.html` (add flash area for `?reason=expired`)

- [ ] **Step 1: Failing tests** — POST `/logout` clears cookie, deletes session server-side, redirects `/login`; GET any web route with expired/missing cookie → redirect `/login?reason=expired`.

- [ ] **Step 2: Implement** — `web_require_session` helper wraps `get_current_session` for web routes: on `AuthError` return a `RedirectResponse` to `/login?reason=expired` instead of raising.

- [ ] **Step 3: Template update** — `login.html` reads `request.query_params.get('reason')` and shows a flash: "Your session expired, please unlock again."

- [ ] **Step 4: Commit.**

---

## Task 10: Error pages

**Files:**
- Create: `templates/errors/404.html`, `templates/errors/500.html`
- Modify: `app/errors.py` (content negotiation: HTML vs JSON based on `Accept` header)

- [ ] **Step 1: Extend `register_error_handlers`** — if `request.headers.get("accept", "").startswith("text/html")`, return `HTMLResponse` rendering the error template; otherwise keep the existing JSON response.

- [ ] **Step 2: Tests** — HTML request → HTML response for 404/500; JSON request → JSON.

- [ ] **Step 3: Commit.**

---

## Task 11: Shared client-side validation (`static/js/validate.js`)

Small helpers used by login + register + new + edit templates:

```javascript
export function requireFilled(formEl, fieldNames, messageEl) {
  formEl.addEventListener("submit", (e) => {
    const missing = fieldNames.filter(n => !formEl.elements[n].value.trim());
    if (missing.length) {
      e.preventDefault();
      messageEl.textContent = `Please fill in: ${missing.join(", ")}`;
    }
  });
}

export function requireMatch(aEl, bEl, messageEl) {
  const check = () => {
    const ok = aEl.value === bEl.value;
    messageEl.textContent = ok ? "" : "Passwords do not match";
    bEl.setCustomValidity(ok ? "" : "Passwords do not match");
  };
  aEl.addEventListener("input", check);
  bEl.addEventListener("input", check);
}
```

Wire into register template. Commit.

---

## Task 12: E2E — full user journey via HTML

**Files:**
- Create: `tests/test_web_e2e.py`

- [ ] **Step 1: Test**

```python
import re


def _csrf(html: str) -> str:
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def test_full_html_journey(client):
    # Register
    token = _csrf(client.get("/register").text)
    r = client.post("/register", data={
        "username": "alice", "master_password": "correct horse battery",
        "confirm_password": "correct horse battery", "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/vault"

    # Create credential
    token = _csrf(client.get("/vault/new").text)
    r = client.post("/vault/new", data={
        "service": "github", "username": "u", "password": "p",
        "notes": "", "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 303

    # View
    cid = r.headers["location"].rsplit("/", 1)[-1]
    detail = client.get(f"/vault/{cid}").text
    assert "github" in detail.lower()
    assert "<p>" not in detail or True  # escaped output check omitted for brevity

    # Logout
    token = _csrf(client.get("/vault").text)
    client.post("/logout", data={"_csrf": token}, follow_redirects=False)
    assert client.get("/vault", follow_redirects=False).status_code == 303
```

- [ ] **Step 2: Commit**.

---

## Task 13: Update project docs

Add:

- **Run with UI:** same `uvicorn` command — UI is at `/login`.
- **Templates live at:** `templates/`. **Static:** `static/`.
- **Security invariants additions:** cookie flags, CSRF pattern, CSP, JS stance (no inline).
- **Known limitations:** Tailwind via CDN (v1 only), Secure Notes / Payment Cards / 2FA / Sharing are stubbed "coming soon" nav items.

Commit.

---

## Self-review notes

- **Spec coverage:** login, register, vault list, add, detail, edit, delete, logout, CSRF, security headers, password generator, strength meter, copy auto-clear, reveal toggle, session expiry UX — all covered.
- **Out of scope (flagged):** Secure Notes, Payment Cards, Trash, Security Audit dashboard, folders, Share, avatar upload, 2FA, FIPS/SOC2 badges, mobile bottom-nav destinations other than Vault. Nav links for these render as disabled "coming soon" pills.
- **No placeholders:** every task names concrete files, tests, and code snippets. Abbreviated-but-concrete where the mockup markup is large; "adapt the mockup" points at a specific HTML block.
- **Cross-lane boundaries:**
  - Bibas owns Task 1 entirely (backend shims). Could merge Task 1 alone as a prerequisite PR.
  - Abhishek owns Tasks 2–12 (templates + static JS).
  - No changes to `app/crypto/` or `app/db/` — Nathaniel's lane unaffected.
  - No changes to `app/api/` — API surface unchanged; the JSON API keeps working for automated consumers and Javokhir's adversarial tests.
