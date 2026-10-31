"""Full page vs HTMX fragment rendering (DESIGN.md §6)."""

from typing import Any

from flask import Response, make_response, render_template, request


def is_htmx_request() -> bool:
    # Boosted links/forms and history restores (Back after `hx-push-url` when HTMX's history cache
    # misses; HTMX still sends HX-Request) swap the whole <body>, so they need the full page.
    headers = request.headers
    return (
        headers.get("HX-Request") == "true"
        and headers.get("HX-Boosted") != "true"
        and headers.get("HX-History-Restore-Request") != "true"
    )


def render_page(template: str, status: int = 200, **context: Any) -> Response:
    """Render a page template; it extends the fragment layout for HTMX requests (`is_htmx`)."""
    response = make_response(render_template(template, **context), status)
    # Same URL, two representations chosen by these headers: caches must key on all of them.
    response.vary.add("HX-Request")
    response.vary.add("HX-Boosted")
    response.vary.add("HX-History-Restore-Request")
    return response
