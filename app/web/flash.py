# one-time flash messages that survive a redirect
# the message is signed and stored in a short-lived cookie, then read and deleted on the next page load

from itsdangerous import BadSignature, URLSafeSerializer

_COOKIE = "mk_flash"


def _serializer(secret: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret, salt="mk-flash")


def read(secret: str, cookie_value: str | None) -> list[tuple[str, str]]:
    if not cookie_value:
        return []
    try:
        data = _serializer(secret).loads(cookie_value)
    except BadSignature:
        return []
    return [(str(c), str(m)) for c, m in data]


def write(secret: str, messages: list[tuple[str, str]]) -> str:
    return _serializer(secret).dumps(messages)


COOKIE_NAME = _COOKIE
