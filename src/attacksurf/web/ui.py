"""HTML UI blueprint (Jinja + HTMX pages)."""

from flask import Blueprint, render_template

bp = Blueprint("ui", __name__)


@bp.get("/")
def index() -> str:
    return render_template("index.html")
