import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from app.auth.jwt import JWTError, decode_token, issue_token
from app.auth.kdf import derive_key, new_salt
from app.auth.password import hash_master_password, verify_master_password
from app.config import get_settings
from app.db import repository as repo
from app.schemas.user import RegisterRequest
from app.web import csrf, flash

router = APIRouter(tags=["web-auth"])


def _issue_session_cookie(
    request: Request,
    response: Response,
    *,
    user_id: int,
    master_password: str,
    kdf_salt: bytes,
) -> Response:
    """Derive the AES key, create a session, mint a JWT, and set ``mk_session``.

    Shared by the login and register success paths so cookie settings stay in
    one place.
    """
    settings = get_settings()
    key = derive_key(master_password, kdf_salt)
    sid = request.app.state.sessions.create(user_id=user_id, key=key)
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
    user = repo.get_user_by_username(settings.db_path, username)
    if user is None or not verify_master_password(master_password, user["bcrypt_hash"]):
        return _redirect_with_flash(
            request, "/login", settings.jwt_secret, [("error", "Invalid credentials")]
        )
    redirect = RedirectResponse(url="/vault", status_code=303)
    return _issue_session_cookie(
        request,
        redirect,
        user_id=user["id"],
        master_password=master_password,
        kdf_salt=user["kdf_salt"],
    )


@router.get("/register", response_class=HTMLResponse, name="web_register_get")
def register_get(request: Request) -> Response:
    return _render_register(request)


@router.post("/register", name="web_register_post")
def register_post(
    request: Request,
    username: str = Form(default=""),
    master_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")

    # Validate with the same schema the JSON API uses.
    try:
        valid = RegisterRequest(username=username, master_password=master_password)
    except ValidationError:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Please check the form")]
        )

    if master_password != confirm_password:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Passwords do not match")]
        )

    kdf_salt = new_salt()
    try:
        uid = repo.create_user(
            settings.db_path,
            username=valid.username,
            bcrypt_hash=hash_master_password(valid.master_password, cost=settings.bcrypt_cost),
            kdf_salt=kdf_salt,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except sqlite3.IntegrityError:
        return _redirect_with_flash(
            request, "/register", settings.jwt_secret, [("error", "Username already taken")]
        )

    redirect = RedirectResponse(url="/vault", status_code=303)
    return _issue_session_cookie(
        request,
        redirect,
        user_id=uid,
        master_password=valid.master_password,
        kdf_salt=kdf_salt,
    )


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
