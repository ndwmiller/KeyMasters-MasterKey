"""Guardrail tests for CSP compliance in Jinja templates.

The production CSP is ``script-src 'self' https://cdn.tailwindcss.com`` with no
``'unsafe-inline'`` and no nonce, so any inline ``<script>`` body or inline
``on*="..."`` event handler attribute is blocked at runtime. FastAPI's
TestClient doesn't execute JS, so without these tests a regression would slip
through silently.
"""

import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


def _iter_html() -> list[Path]:
    return list(TEMPLATES.rglob("*.html"))


def test_no_inline_script_bodies() -> None:
    """A ``<script>`` tag must either have ``src=...`` or an empty body."""
    pattern = re.compile(
        r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>",
        re.DOTALL | re.IGNORECASE,
    )
    offenders: list[str] = []
    for path in _iter_html():
        text = path.read_text()
        for m in pattern.finditer(text):
            attrs = m.group("attrs")
            body = m.group("body").strip()
            if body and "src=" not in attrs.lower():
                offenders.append(
                    f"{path.relative_to(TEMPLATES.parent)}: inline script body"
                )
    assert not offenders, "\n".join(offenders)


def test_no_inline_event_handlers() -> None:
    """Inline ``on*=`` attributes (onclick, onsubmit, onchange, ...) are blocked."""
    pattern = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
    offenders: list[str] = []
    for path in _iter_html():
        text = path.read_text()
        for m in pattern.finditer(text):
            offenders.append(
                f"{path.relative_to(TEMPLATES.parent)}: {m.group(0).strip()}"
            )
    assert not offenders, "\n".join(offenders)
