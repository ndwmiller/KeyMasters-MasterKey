"""Smoke test for the Jinja2 base template (Task 2).

Confirms that `templates/base.html` and its included partials parse and render
without error, and that the key static/CDN references are emitted so the
CSP-compliant load order (local Tailwind config before the CDN script) is
actually in the output.
"""

from starlette.requests import Request

from app.main import create_app


def _make_request(app) -> Request:
    """Build a minimal ASGI Request bound to the app so `url_for` works."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "app": app,
        "scheme": "http",
        "server": ("testserver", 80),
        "root_path": "",
        "client": ("testclient", 50000),
    }
    return Request(scope)


def test_base_template_renders(db_path):
    app = create_app()
    templates = app.state.templates
    request = _make_request(app)

    html = templates.get_template("base.html").render({"request": request})

    assert "<title>Master Key</title>" in html
    assert "tailwind-config.js" in html
    assert "cdn.tailwindcss.com" in html
    assert "app.css" in html


def test_base_template_loads_config_before_cdn(db_path):
    """CSP forbids inline scripts, so `tailwind.config` must be in a served
    file loaded BEFORE the Tailwind CDN runtime parses it.
    """
    app = create_app()
    templates = app.state.templates
    request = _make_request(app)

    html = templates.get_template("base.html").render({"request": request})

    config_pos = html.find("tailwind-config.js")
    cdn_pos = html.find("cdn.tailwindcss.com")
    assert config_pos != -1 and cdn_pos != -1
    assert config_pos < cdn_pos, "tailwind-config.js must load before the CDN script"
