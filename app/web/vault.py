from fastapi import APIRouter, Cookie, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import get_settings
from app.db import repository as repo
from app.web import flash
from app.web.deps import try_current_session

router = APIRouter(tags=["web-vault"])


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
