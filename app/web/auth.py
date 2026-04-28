# html form routes for login, register, and logout
# mirrors the json api in app/api/auth.py but renders html pages and sets cookies instead of returning tokens

import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from app.auth.jwt import JWTError, decode_token, issue_token
from app.auth.kdf import derive_key, derive_recovery_key, new_salt
from app.auth.password import (
    hash_master_password,
    validate_master_password,
    verify_master_password,
)
from app.auth.recovery_questions import RECOVERY_QUESTIONS, is_valid_question
from app.config import get_settings
from app.crypto.encryption import new_mek, unwrap_key, wrap_key
from app.db import repository as repo
from app.schemas.user import RegisterRequest
from app.web import csrf, flash

router = APIRouter(tags=["web-auth"])


def _issue_session_cookie(
    request: Request,
    response: Response,
    *,
    user_id: int,
    session_key: bytes,
) -> Response:
    """Create a session, mint a JWT, and set ``mk_session``."""
    settings = get_settings()
    sid = request.app.state.sessions.create(user_id=user_id, key=session_key)
    token = issue_token(
        {"sub": str(user_id), "sid": sid},
        settings.jwt_secret,
        ttl=timedelta(minutes=settings.jwt_ttl_minutes),
        algorithm=settings.jwt_algorithm,
    )
    # secure=True prevents the cookie from being sent over plain http.
    # we only enable it when the connection is already https so localhost still works.
    response.set_cookie(
        "mk_session",
        token,
        max_age=settings.jwt_ttl_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    response.delete_cookie(csrf.COOKIE_NAME, path="/")
    return response


def _render_login(request: Request, reason: str | None, error: str | None) -> Response:
    settings = get_settings()
    token = csrf.ensure_token(settings.jwt_secret, request.cookies.get(csrf.COOKIE_NAME))
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    if error:
        flashes = [*flashes, ("error", error)]
    if reason == "required":
        flashes = [*flashes, ("info", "Please unlock the vault to continue.")]
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "auth/login.html",
        {"csrf_token": token, "flashes": flashes},
    )
    response.set_cookie(
        csrf.COOKIE_NAME,
        token,
        max_age=15 * 60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    # Clear consumed flashes
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


def _render_register(request: Request) -> Response:
    settings = get_settings()
    token = csrf.ensure_token(settings.jwt_secret, request.cookies.get(csrf.COOKIE_NAME))
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "auth/register.html",
        {
            "csrf_token": token,
            "flashes": flashes,
            "recovery_questions": RECOVERY_QUESTIONS,
        },
    )
    response.set_cookie(
        csrf.COOKIE_NAME,
        token,
        max_age=15 * 60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


def _redirect_with_flash(request: Request, url: str, secret: str, messages: list[tuple[str, str]]) -> RedirectResponse:
    redirect = RedirectResponse(url=url, status_code=303)
    redirect.set_cookie(
        flash.COOKIE_NAME,
        flash.write(secret, messages),
        max_age=60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return redirect


@router.get("/login", response_class=HTMLResponse, name="web_login_get")
def login_get(request: Request, reason: str | None = None) -> Response:
    return _render_login(request, reason=reason, error=None)


@router.post("/login", name="web_login_post")
def login_post(
    request: Request,
    username: str = Form(default=""),
    master_password: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")
    limiter = request.app.state.rate_limiter
    if limiter.is_blocked(username):
        return _redirect_with_flash(
            request, "/login", settings.jwt_secret, [("error", "Too many failed attempts, try again later")]
        )
    user = repo.get_user_by_username(settings.db_path, username)
    if user is None or not verify_master_password(master_password, user["bcrypt_hash"]):
        limiter.record_failure(username)
        return _redirect_with_flash(
            request, "/login", settings.jwt_secret, [("error", "Invalid credentials")]
        )
    kek = derive_key(master_password, user["kdf_salt"])
    try:
        mek = unwrap_key(kek, user["master_wrapped_mek"])
    except InvalidTag:
        # Wrap should always open if bcrypt accepted; treat as a failed login
        # to avoid leaking which factor disagreed.
        limiter.record_failure(username)
        return _redirect_with_flash(
            request, "/login", settings.jwt_secret, [("error", "Invalid credentials")]
        )
    limiter.clear(username)
    redirect = RedirectResponse(url="/vault", status_code=303)
    return _issue_session_cookie(request, redirect, user_id=user["id"], session_key=mek)


@router.get("/register", response_class=HTMLResponse, name="web_register_get")
def register_get(request: Request) -> Response:
    return _render_register(request)


@router.post("/register", name="web_register_post")
def register_post(
    request: Request,
    username: str = Form(default=""),
    master_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
    recovery_q1: str = Form(default=""),
    recovery_a1: str = Form(default=""),
    recovery_q2: str = Form(default=""),
    recovery_a2: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")

    try:
        valid = RegisterRequest(
            username=username,
            master_password=master_password,
            recovery_q1=recovery_q1,
            recovery_a1=recovery_a1,
            recovery_q2=recovery_q2,
            recovery_a2=recovery_a2,
        )
    except ValidationError:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Password must be at least 12 characters and contain an uppercase letter, a lowercase letter, and a symbol")]
        )

    if master_password != confirm_password:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Passwords do not match")]
        )

    mek = new_mek()
    mp_salt = new_salt()
    rec_salt = new_salt()
    master_kek = derive_key(valid.master_password, mp_salt)
    recovery_kek = derive_recovery_key(valid.recovery_a1, valid.recovery_a2, rec_salt)
    try:
        uid = repo.create_user(
            settings.db_path,
            username=valid.username,
            bcrypt_hash=hash_master_password(valid.master_password, cost=settings.bcrypt_cost),
            kdf_salt=mp_salt,
            master_wrapped_mek=wrap_key(master_kek, mek),
            recovery_salt=rec_salt,
            recovery_q1=valid.recovery_q1,
            recovery_q2=valid.recovery_q2,
            recovery_wrapped_mek=wrap_key(recovery_kek, mek),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except sqlite3.IntegrityError:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Username already taken")]
        )

    redirect = RedirectResponse(url="/vault", status_code=303)
    return _issue_session_cookie(request, redirect, user_id=uid, session_key=mek)


@router.post("/logout", name="web_logout")
def logout_post(
    request: Request,
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")

    # Best-effort session cleanup. Logout is idempotent — if the token is
    # missing or undecodable, we still clear cookies and redirect.
    if mk_session:
        try:
            claims = decode_token(
                mk_session,
                settings.jwt_secret,
                algorithm=settings.jwt_algorithm,
            )
            sid = claims.get("sid")
            if isinstance(sid, str):
                request.app.state.sessions.delete(sid)
        except JWTError:
            pass

    redirect = _redirect_with_flash(
        request,
        "/login",
        settings.jwt_secret,
        [("success", "You have been locked out.")],
    )
    redirect.delete_cookie("mk_session", path="/")
    redirect.delete_cookie(csrf.COOKIE_NAME, path="/")
    return redirect


@router.get("/forgot-password", response_class=HTMLResponse, name="web_forgot_get")
def forgot_get(request: Request) -> Response:
    settings = get_settings()
    token = csrf.ensure_token(settings.jwt_secret, request.cookies.get(csrf.COOKIE_NAME))
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "auth/forgot.html",
        {
            "csrf_token": token,
            "flashes": flashes,
            "step": "lookup",
            "username": "",
            "questions": None,
        },
    )
    response.set_cookie(
        csrf.COOKIE_NAME,
        token,
        max_age=15 * 60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


@router.post("/forgot-password", name="web_forgot_lookup")
def forgot_lookup(
    request: Request,
    username: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")
    user = repo.get_user_by_username(settings.db_path, username.strip())
    if user is None:
        return _redirect_with_flash(
            request,
            "/forgot-password",
            settings.jwt_secret,
            [("error", "No vault was found for that username.")],
        )
    token = csrf.ensure_token(settings.jwt_secret, request.cookies.get(csrf.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "auth/forgot.html",
        {
            "csrf_token": token,
            "flashes": [],
            "step": "answer",
            "username": user["username"],
            "questions": (user["recovery_q1"], user["recovery_q2"]),
        },
    )
    response.set_cookie(
        csrf.COOKIE_NAME,
        token,
        max_age=15 * 60,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


@router.post("/forgot-password/recover", name="web_forgot_recover")
def forgot_recover(
    request: Request,
    username: str = Form(default=""),
    answer1: str = Form(default=""),
    answer2: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")

    if new_password != confirm_password:
        return _redirect_with_flash(
            request,
            "/forgot-password",
            settings.jwt_secret,
            [("error", "New password and confirmation do not match.")],
        )
    err = validate_master_password(new_password)
    if err is not None:
        return _redirect_with_flash(
            request,
            "/forgot-password",
            settings.jwt_secret,
            [("error", f"New password {err}.")],
        )

    user = repo.get_user_by_username(settings.db_path, username.strip())
    if user is None:
        return _redirect_with_flash(
            request, "/forgot-password", settings.jwt_secret,
            [("error", "Recovery failed. Please verify your answers.")],
        )

    recovery_kek = derive_recovery_key(answer1, answer2, user["recovery_salt"])
    try:
        mek = unwrap_key(recovery_kek, user["recovery_wrapped_mek"])
    except InvalidTag:
        return _redirect_with_flash(
            request, "/forgot-password", settings.jwt_secret,
            [("error", "Recovery failed. Please verify your answers.")],
        )

    new_mp_salt = new_salt()
    new_master_kek = derive_key(new_password, new_mp_salt)
    repo.update_user_master_password(
        settings.db_path,
        user_id=user["id"],
        bcrypt_hash=hash_master_password(new_password, cost=settings.bcrypt_cost),
        kdf_salt=new_mp_salt,
        master_wrapped_mek=wrap_key(new_master_kek, mek),
    )
    return _redirect_with_flash(
        request, "/login", settings.jwt_secret,
        [("success", "Master password reset. Please unlock your vault.")],
    )
