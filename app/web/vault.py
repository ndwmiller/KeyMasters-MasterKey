from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from app.config import get_settings
from app.crypto.encryption import decrypt_credential, encrypt_credential
from app.db import repository as repo
from app.schemas.credential import CredentialCreate, CredentialUpdate
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
    token = csrf.issue_token(settings.jwt_secret)
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/list.html",
        {
            "credentials": credentials,
            "csrf_token": token,
            "active_nav": "vault",
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


@router.get("/vault/{cid}", response_class=HTMLResponse, name="web_vault_detail")
def vault_detail(
    cid: int,
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    settings = get_settings()
    row = repo.get_credential(settings.db_path, cid=cid, user_id=session.user_id)
    if row is None:
        return _redirect_with_flash(
            "/vault",
            settings.jwt_secret,
            [("error", "Credential not found")],
        )
    credential = {
        "id": row["id"],
        "service": row["service"],
        "username": decrypt_credential(session.key, row["username_enc"]),
        "password": decrypt_credential(session.key, row["password_enc"]),
        "notes": (
            decrypt_credential(session.key, row["notes_enc"])
            if row["notes_enc"] is not None
            else None
        ),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    token = csrf.issue_token(settings.jwt_secret)
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/detail.html",
        {
            "credential": credential,
            "csrf_token": token,
            "active_nav": "vault",
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


@router.get("/vault/{cid}/edit", response_class=HTMLResponse, name="web_vault_edit")
def vault_edit_get(
    cid: int,
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    settings = get_settings()
    row = repo.get_credential(settings.db_path, cid=cid, user_id=session.user_id)
    if row is None:
        return _redirect_with_flash(
            "/vault",
            settings.jwt_secret,
            [("error", "Credential not found")],
        )
    credential = {
        "id": row["id"],
        "service": row["service"],
        "username": decrypt_credential(session.key, row["username_enc"]),
        "password": decrypt_credential(session.key, row["password_enc"]),
        "notes": (
            decrypt_credential(session.key, row["notes_enc"])
            if row["notes_enc"] is not None
            else ""
        ),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    token = csrf.issue_token(settings.jwt_secret)
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/edit.html",
        {
            "credential": credential,
            "csrf_token": token,
            "active_nav": "vault",
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


@router.post("/vault/{cid}/edit", name="web_vault_edit_post")
def vault_edit_post(
    cid: int,
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

    existing = repo.get_credential(settings.db_path, cid=cid, user_id=session.user_id)
    if existing is None:
        return _redirect_with_flash(
            "/vault",
            settings.jwt_secret,
            [("error", "Credential not found")],
        )

    try:
        valid = CredentialUpdate(
            service=service or None,
            username=username if username != "" else None,
            password=password or None,
            notes=notes or None,
        )
    except ValidationError:
        return _redirect_with_flash(
            f"/vault/{cid}/edit",
            settings.jwt_secret,
            [("error", "Please check the form")],
        )

    current_username = decrypt_credential(session.key, existing["username_enc"])
    current_password = decrypt_credential(session.key, existing["password_enc"])
    current_notes = (
        decrypt_credential(session.key, existing["notes_enc"])
        if existing["notes_enc"] is not None
        else None
    )

    merged_service = valid.service if valid.service is not None else existing["service"]
    merged_username = valid.username if valid.username is not None else current_username
    merged_password = valid.password if valid.password is not None else current_password
    merged_notes = valid.notes if valid.notes is not None else current_notes

    u_enc = encrypt_credential(session.key, merged_username)
    p_enc = encrypt_credential(session.key, merged_password)
    n_enc = encrypt_credential(session.key, merged_notes) if merged_notes is not None else None
    now = datetime.now(timezone.utc).isoformat()
    repo.update_credential(
        settings.db_path,
        cid=cid,
        user_id=session.user_id,
        service=merged_service,
        username_enc=u_enc,
        password_enc=p_enc,
        notes_enc=n_enc,
        updated_at=now,
    )
    return _redirect_with_flash(
        f"/vault/{cid}",
        settings.jwt_secret,
        [("success", "Credential updated")],
    )


@router.post("/vault/{cid}/delete", name="web_vault_delete")
def vault_delete(
    cid: int,
    request: Request,
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
    ok = repo.delete_credential(settings.db_path, cid=cid, user_id=session.user_id)
    if not ok:
        return _redirect_with_flash(
            "/vault",
            settings.jwt_secret,
            [("error", "Credential not found")],
        )
    return _redirect_with_flash(
        "/vault",
        settings.jwt_secret,
        [("success", "Credential deleted")],
    )
