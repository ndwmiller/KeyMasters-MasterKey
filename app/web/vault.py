from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from app.config import get_settings
from app.crypto.encryption import encrypt_credential
from app.db import repository as repo
from app.schemas.credential import CredentialCreate
from app.web import csrf, flash
from app.web.deps import try_current_session

router = APIRouter(tags=["web-vault"])


def _redirect_with_flash(
    url: str, secret: str, messages: list[tuple[str, str]]
) -> RedirectResponse:
    redirect = RedirectResponse(url=url, status_code=303)
    redirect.set_cookie(
        flash.COOKIE_NAME,
        flash.write(secret, messages),
        max_age=60,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    return redirect


@router.get("/", include_in_schema=False, name="web_root")
def index(
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/vault", status_code=303)


@router.get("/vault", response_class=HTMLResponse, name="web_vault_list")
def vault_list(
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    settings = get_settings()
    credentials = repo.list_credentials_for_user(settings.db_path, session.user_id)
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/list.html",
        {
            "credentials": credentials,
            "active_nav": "vault",
            "flashes": flashes,
        },
    )
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


@router.get("/vault/new", response_class=HTMLResponse, name="web_vault_new_get")
def vault_new_get(
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    settings = get_settings()
    token = csrf.issue_token(settings.jwt_secret)
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/new.html",
        {
            "csrf_token": token,
            "active_nav": "new",
            "flashes": flashes,
        },
    )
    response.set_cookie(
        csrf.COOKIE_NAME,
        token,
        max_age=15 * 60,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


@router.post("/vault/new", name="web_vault_new_post")
def vault_new_post(
    request: Request,
    service: str = Form(default=""),
    username: str = Form(default=""),
    password: str = Form(default=""),
    notes: str = Form(default=""),
    csrf_token: str | None = Form(default=None, alias="_csrf"),
    mk_csrf: str | None = Cookie(default=None),
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    settings = get_settings()
    if not csrf.validate(settings.jwt_secret, mk_csrf, csrf_token):
        raise HTTPException(status_code=403, detail="csrf failed")
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)

    try:
        valid = CredentialCreate(
            service=service,
            username=username,
            password=password,
            notes=(notes or None),
        )
    except ValidationError:
        return _redirect_with_flash(
            "/vault/new",
            settings.jwt_secret,
            [("error", "Please check the form")],
        )

    u_enc = encrypt_credential(session.key, valid.username)
    p_enc = encrypt_credential(session.key, valid.password)
    n_enc = encrypt_credential(session.key, valid.notes) if valid.notes is not None else None
    now = datetime.now(timezone.utc).isoformat()
    cid = repo.create_credential(
        settings.db_path,
        user_id=session.user_id,
        service=valid.service,
        username_enc=u_enc,
        password_enc=p_enc,
        notes_enc=n_enc,
        created_at=now,
        updated_at=now,
    )
    return _redirect_with_flash(
        f"/vault/{cid}",
        settings.jwt_secret,
        [("success", "Credential saved")],
    )
