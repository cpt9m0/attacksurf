"""Full page vs HTMX fragment rendering (DESIGN.md §6)."""

from typing import Any

from flask import Response, make_response, render_template, request


def is_htmx_request() -> bool:
    # Boosted links/forms swap the whole <body>, so they need the full page.
    return (
        request.headers.get("HX-Request") == "true" and request.headers.get("HX-Boosted") != "true"
    )


def render_page(template: str, status: int = 200, **context: Any) -> Response:
    """Render a page template; it extends the fragment layout for HTMX requests (`is_htmx`)."""
    response = make_response(render_template(template, **context), status)
    # Same URL, two representations: caches must key on the header.
    response.vary.add("HX-Request")
    return response
