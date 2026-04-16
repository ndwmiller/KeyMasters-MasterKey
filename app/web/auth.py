from datetime import timedelta

from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth.jwt import issue_token
from app.auth.kdf import derive_key
from app.auth.password import verify_master_password
from app.config import get_settings
from app.db import repository as repo
from app.web import csrf, flash

router = APIRouter(tags=["web-auth"])


def _render_login(request: Request, reason: str | None, error: str | None) -> Response:
    settings = get_settings()
    token = csrf.issue_token(settings.jwt_secret)
    flashes = flash.read(settings.jwt_secret, request.cookies.get(flash.COOKIE_NAME))
    if error:
        flashes = [*flashes, ("error", error)]
    if reason == "expired":
        flashes = [*flashes, ("info", "Your session expired, please unlock again.")]
    elif reason == "required":
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
        secure=False,
        path="/",
    )
    # Clear consumed flashes
    response.delete_cookie(flash.COOKIE_NAME, path="/")
    return response


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
        redirect = RedirectResponse(url="/login", status_code=303)
        redirect.set_cookie(
            flash.COOKIE_NAME,
            flash.write(settings.jwt_secret, [("error", "Invalid credentials")]),
            max_age=60,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        return redirect
    key = derive_key(master_password, user["kdf_salt"])
    sid = request.app.state.sessions.create(user_id=user["id"], key=key)
    token = issue_token(
        {"sub": str(user["id"]), "sid": sid},
        settings.jwt_secret,
        ttl=timedelta(minutes=settings.jwt_ttl_minutes),
        algorithm=settings.jwt_algorithm,
    )
    redirect = RedirectResponse(url="/vault", status_code=303)
    redirect.set_cookie(
        "mk_session",
        token,
        max_age=settings.jwt_ttl_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    redirect.delete_cookie(csrf.COOKIE_NAME, path="/")
    return redirect
