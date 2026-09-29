from flask import Blueprint, render_template

from .. import repository as repo

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    return render_template(
        "dashboard.html",
        counts=repo.counts(),
        alerts=repo.list_alerts(limit=5),
        analyses=repo.list_analyses(limit=5),
    )
