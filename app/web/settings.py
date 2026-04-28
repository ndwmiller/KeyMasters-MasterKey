# html routes for the settings page: account info, change master password,
# update security questions, delete account.
#
# Every state-changing route requires the user's current master password as a
# second-factor confirmation, even though the session is already authenticated.
# This blocks "stolen session cookie" attacks from rotating the wrap or
# nuking the account.

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Cookie, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.auth.kdf import derive_key, derive_recovery_key, new_salt
from app.auth.password import (
    hash_master_password,
    validate_master_password,
    verify_master_password,
)
from app.auth.recovery_questions import RECOVERY_QUESTIONS, is_valid_question
from app.config import get_settings
from app.crypto.encryption import unwrap_key, wrap_key
from app.db import repository as repo
from app.web import csrf, flash
from app.web.deps import try_current_session

router = APIRouter(tags=["web-settings"])


def _redirect_with_flash(
    request: Request, url: str, secret: str, messages: list[tuple[str, str]]
) -> RedirectResponse:
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


@router.get("/vault/settings", response_class=HTMLResponse, name="web_vault_settings")
def settings_get(
    request: Request,
    authorization: str = Header(default=""),
    mk_session: str | None = Cookie(default=None),
) -> Response:
    sessions = request.app.state.sessions
    session = try_current_session(authorization, mk_session, sessions)
    if session is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    settings = get_settings()
    user = repo.get_user_by_id(settings.db_path, session.user_id)
    if user is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)
    rows = repo.list_credentials_for_user(settings.db_path, session.user_id)
    token = csrf.ensure_token(settings.jwt_secret, request.cookies.get(csrf.COOKIE_NAME))
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    templates = request.app.state.templates
    response = templates.TemplateResponse(
        request,
        "vault/settings.html",
        {
            "csrf_token": token,
            "active_nav": "settings",
            "flashes": flashes,
            "account": {
                "username": user["username"],
                "created_at": user["created_at"],
                "credential_count": len(rows),
            },
            "recovery": {
                "q1": user["recovery_q1"],
                "q2": user["recovery_q2"],
            },
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


@router.post("/vault/settings/change-password", name="web_settings_change_password")
def change_password(
    request: Request,
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
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
    user = repo.get_user_by_id(settings.db_path, session.user_id)
    if user is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)

    if not verify_master_password(current_password, user["bcrypt_hash"]):
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Current password is incorrect.")],
        )
    err = validate_master_password(new_password)
    if err is not None:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", f"New password {err}.")],
        )
    if new_password != confirm_password:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "New password and confirmation do not match.")],
        )

    # Re-wrap the existing MEK with a KEK derived from the new password.
    # session.key already holds the unwrapped MEK, but we re-derive from the
    # current password to be defensive: if the session were poisoned somehow,
    # we'd notice the wrap mismatch here.
    old_kek = derive_key(current_password, user["kdf_salt"])
    try:
        mek = unwrap_key(old_kek, user["master_wrapped_mek"])
    except InvalidTag:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Current password is incorrect.")],
        )
    new_mp_salt = new_salt()
    new_kek = derive_key(new_password, new_mp_salt)
    repo.update_user_master_password(
        settings.db_path,
        user_id=user["id"],
        bcrypt_hash=hash_master_password(new_password, cost=settings.bcrypt_cost),
        kdf_salt=new_mp_salt,
        master_wrapped_mek=wrap_key(new_kek, mek),
    )
    return _redirect_with_flash(
        request, "/vault/settings", settings.jwt_secret,
        [("success", "Master password updated.")],
    )


@router.post("/vault/settings/update-questions", name="web_settings_update_questions")
def update_questions(
    request: Request,
    current_password: str = Form(default=""),
    recovery_q1: str = Form(default=""),
    recovery_a1: str = Form(default=""),
    recovery_q2: str = Form(default=""),
    recovery_a2: str = Form(default=""),
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
    user = repo.get_user_by_id(settings.db_path, session.user_id)
    if user is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)

    if not verify_master_password(current_password, user["bcrypt_hash"]):
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Current password is incorrect.")],
        )
    if not is_valid_question(recovery_q1) or not is_valid_question(recovery_q2):
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Please pick two questions from the list.")],
        )
    if recovery_q1 == recovery_q2:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Pick two different questions.")],
        )
    if not recovery_a1.strip() or not recovery_a2.strip():
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Both answers are required.")],
        )

    kek = derive_key(current_password, user["kdf_salt"])
    try:
        mek = unwrap_key(kek, user["master_wrapped_mek"])
    except InvalidTag:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Current password is incorrect.")],
        )
    new_rec_salt = new_salt()
    recovery_kek = derive_recovery_key(recovery_a1, recovery_a2, new_rec_salt)
    repo.update_user_recovery(
        settings.db_path,
        user_id=user["id"],
        recovery_salt=new_rec_salt,
        recovery_q1=recovery_q1,
        recovery_q2=recovery_q2,
        recovery_wrapped_mek=wrap_key(recovery_kek, mek),
    )
    return _redirect_with_flash(
        request, "/vault/settings", settings.jwt_secret,
        [("success", "Recovery questions updated.")],
    )


@router.post("/vault/settings/delete-account", name="web_settings_delete_account")
def delete_account(
    request: Request,
    confirm_username: str = Form(default=""),
    current_password: str = Form(default=""),
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
    user = repo.get_user_by_id(settings.db_path, session.user_id)
    if user is None:
        return RedirectResponse(url="/login?reason=required", status_code=303)

    if confirm_username != user["username"]:
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Confirmation username does not match.")],
        )
    if not verify_master_password(current_password, user["bcrypt_hash"]):
        return _redirect_with_flash(
            request, "/vault/settings", settings.jwt_secret,
            [("error", "Current password is incorrect.")],
        )

    # Cascade delete: removes the user row and (via ON DELETE CASCADE) every
    # encrypted credential row owned by them.
    repo.delete_user(settings.db_path, user_id=user["id"])

    # Tear down the in-memory session too — the JWT cookie is harmless after
    # the user row is gone, but cleaning up keeps the session store small.
    if mk_session:
        from app.auth.jwt import JWTError, decode_token
        try:
            claims = decode_token(mk_session, settings.jwt_secret)
            sid = claims.get("sid")
            if isinstance(sid, str):
                sessions.delete(sid)
        except JWTError:
            pass

    redirect = _redirect_with_flash(
        request, "/login", settings.jwt_secret,
        [("success", "Your account and all credentials were deleted.")],
    )
    redirect.delete_cookie("mk_session", path="/")
    redirect.delete_cookie(csrf.COOKIE_NAME, path="/")
    return redirect
