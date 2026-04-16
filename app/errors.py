import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("master_key")


class AuthError(Exception):
    pass


class NotFoundError(Exception):
    pass


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def _auth(_: Request, __: AuthError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "authentication failed"})

    @app.exception_handler(NotFoundError)
    async def _nf(_: Request, __: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": "not found"})

    @app.exception_handler(Exception)
    async def _generic(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"detail": "internal error"})
