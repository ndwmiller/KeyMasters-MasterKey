import hmac
import secrets

from itsdangerous import BadSignature, URLSafeSerializer

_COOKIE_NAME = "mk_csrf"
_FORM_FIELD = "_csrf"


def _serializer(secret: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret, salt="mk-csrf")


def issue_token(secret: str) -> str:
    return _serializer(secret).dumps(secrets.token_urlsafe(16))


def validate(secret: str, cookie_value: str | None, form_value: str | None) -> bool:
    if not cookie_value or not form_value:
        return False
    if not hmac.compare_digest(cookie_value, form_value):
        return False
    try:
        _serializer(secret).loads(cookie_value)
    except BadSignature:
        return False
    return True


COOKIE_NAME = _COOKIE_NAME
FORM_FIELD = _FORM_FIELD
