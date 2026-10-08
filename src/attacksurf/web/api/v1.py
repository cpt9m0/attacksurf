"""JSON API v1 blueprint. Routes are added per feature (assets, scans, findings)."""

from flask import Blueprint

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
