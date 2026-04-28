# this is the entry point for the application
# uvicorn calls create_app() via the --factory flag so a fresh instance is built on startup

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.auth.rate_limiter import LoginRateLimiter
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.db.connection import init_schema
from app.errors import register_error_handlers
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.web.auth import router as web_auth_router
from app.web.settings import router as web_settings_router
from app.web.vault import router as web_vault_router

_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(_ROOT / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="Master Key", version="0.1.0")
    settings = get_settings()
    init_schema(settings.db_path)

    # these objects live on app.state so any route can reach them via request.app.state
    app.state.sessions = SessionStore(ttl_seconds=settings.session_ttl_minutes * 60)
    app.state.rate_limiter = LoginRateLimiter()
    app.state.templates = TEMPLATES

    app.add_middleware(SecurityHeadersMiddleware)
    register_error_handlers(app)

    # api routers handle json requests, web routers handle html form submissions
    app.include_router(auth_router)
    app.include_router(credentials_router)
    app.include_router(web_auth_router)
    # settings router must come before the catch-all vault router so that
    # /vault/settings is matched as a literal path before the /vault/{cid:int}
    # dynamic route is even considered
    app.include_router(web_settings_router)
    app.include_router(web_vault_router)

    static_dir = _ROOT / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
