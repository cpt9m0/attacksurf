"""Error pages (HTML) and JSON errors for the API."""

from http import HTTPStatus

import structlog
from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException, InternalServerError

from attacksurf.web.rendering import render_page

log = structlog.get_logger(__name__)

_BODY_HEADERS = {"content-type", "content-length"}

_MESSAGES = {
    403: "You don't have permission to view this page.",
    404: "We couldn't find that page. It may have moved or never existed.",
    500: "Something went wrong on our side. Try again; if it keeps happening, report it with "
    "the request ID below.",
}


def init_error_handlers(app: Flask) -> None:
    app.register_error_handler(HTTPException, _handle_http_error)
    app.register_error_handler(Exception, _handle_unexpected_error)


def _handle_http_error(error: HTTPException) -> Response:
    code = error.code or 500
    if request.path.startswith("/api/"):
        response = jsonify(error=error.name)
        response.status_code = code
    else:
        response = _error_page(error, code)
    # Keep protocol headers the exception carries (Allow on 405, Retry-After on 429, ...).
    for name, value in error.get_response().headers.items():
        if name.lower() not in _BODY_HEADERS:
            response.headers[name] = value
    return response


def _error_page(error: HTTPException, code: int) -> Response:
    # Static, safe text only: never echo exception details or request data back.
    return render_page(
        "errors/error.html",
        status=code,
        code=code,
        title=error.name,
        message=_MESSAGES.get(code, error.name),
        # Server errors show the request ID so a report can be matched to the logs.
        request_id=g.get("request_id") if code >= HTTPStatus.INTERNAL_SERVER_ERROR else None,
    )


def _handle_unexpected_error(error: Exception) -> Response:
    log.exception("unhandled exception", path=request.path)
    return _handle_http_error(InternalServerError())
