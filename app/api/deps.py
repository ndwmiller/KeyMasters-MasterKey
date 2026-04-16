from fastapi import Request

from app.auth.session_store import SessionStore


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.sessions
