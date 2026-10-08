"""Liveness endpoint for load balancers and Docker health checks."""

from flask import Blueprint

bp = Blueprint("health", __name__)


@bp.get("/healthz")
def healthz() -> dict[str, str]:
    # Liveness only. Dependency checks (DB, Redis) belong in a readiness probe once they exist.
    return {"status": "ok"}
