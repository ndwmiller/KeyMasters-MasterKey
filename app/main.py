from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.auth.session_store import SessionStore
from app.config import get_settings
from app.errors import register_error_handlers


def create_app() -> FastAPI:
    app = FastAPI(title="Master Key", version="0.1.0")
    settings = get_settings()
    app.state.sessions = SessionStore(ttl_seconds=settings.session_ttl_minutes * 60)
    register_error_handlers(app)
    app.include_router(auth_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
