"""HTTP security headers (docs/security.md)."""

from flask import Flask, Response

from attacksurf.config import Settings

# Same-origin only, no inline script/style and no eval: vendored HTMX and the Alpine CSP build
# work under it. Changing this weakens XSS defenses for scan-derived content; see AGENTS.md.
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)
HSTS = "max-age=63072000; includeSubDomains"


def init_security_headers(app: Flask, settings: Settings) -> None:
    headers = {
        "Content-Security-Policy": CONTENT_SECURITY_POLICY,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    if settings.is_prod:
        # Only behind TLS (Caddy in prod); in dev it would pin localhost to HTTPS.
        headers["Strict-Transport-Security"] = HSTS

    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        for name, value in headers.items():
            response.headers.setdefault(name, value)
        return response
