from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import register_error_handlers
from app.middleware.security_headers import SecurityHeadersMiddleware

_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(_ROOT / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="Master Key", version="0.1.0")
    settings = get_settings()
    app.state.sessions = SessionStore(ttl_seconds=settings.session_ttl_minutes * 60)
    app.state.templates = TEMPLATES
    app.add_middleware(SecurityHeadersMiddleware)
    register_error_handlers(app)
    app.include_router(auth_router)
    app.include_router(credentials_router)
    static_dir = _ROOT / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
