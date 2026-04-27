# centralizes error handling so internal details never reach the client
# unexpected exceptions log the full traceback server-side but only return a generic message

import logging

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("master_key")


class AuthError(Exception):
    pass


class NotFoundError(Exception):
    pass


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "").lower()


def _render_error_html(
    request: Request, status_code: int, template: str
) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        template,
        {},
        status_code=status_code,
    )


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def _auth(_: Request, __: AuthError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "authentication failed"})

    @app.exception_handler(NotFoundError)
    async def _nf(request: Request, _exc: NotFoundError) -> Response:
        if _wants_html(request):
            return _render_error_html(request, 404, "errors/404.html")
        return JSONResponse(status_code=404, content={"detail": "not found"})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        if _wants_html(request) and exc.status_code == 404:
            return _render_error_html(request, 404, "errors/404.html")
        # Default: preserve FastAPI's normal JSON behavior.
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.detail}
        )

    @app.exception_handler(Exception)
    async def _generic(request: Request, exc: Exception) -> Response:
        log.exception("unhandled error: %s", exc)
        if _wants_html(request):
            return _render_error_html(request, 500, "errors/500.html")
        return JSONResponse(status_code=500, content={"detail": "internal error"})
