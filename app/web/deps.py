"""Web-friendly session helpers.

Unlike ``app.api.deps.get_current_session``, these return ``None`` when the
caller is unauthenticated instead of raising ``AuthError``. The web routes can
then redirect to ``/login?reason=required`` rather than return a 401 JSON
response.
"""

from app.api.deps import CurrentSession
from app.auth.jwt import JWTError, decode_token
from app.auth.session_store import SessionStore
from app.config import get_settings


def try_current_session(
    authorization: str,
    mk_session: str | None,
    sessions: SessionStore,
) -> CurrentSession | None:
    """Return a ``CurrentSession`` if the request is authenticated, else ``None``.

    Mirrors the token-extraction logic in ``app.api.deps`` so that both the
    ``Authorization: Bearer`` header and the ``mk_session`` cookie are
    accepted. Never raises for bad/missing tokens — callers decide what to do
    when ``None`` is returned (typically a ``303`` redirect to ``/login``).
    """
    settings = get_settings()
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    elif mk_session:
        token = mk_session
    else:
        return None
    try:
        claims = decode_token(token, settings.jwt_secret)
    except JWTError:
        return None
    sid = claims.get("sid")
    if not sid:
        return None
    entry = sessions.get(sid)
    if entry is None:
        return None
    user_id, key = entry
    return CurrentSession(user_id=user_id, key=key)
