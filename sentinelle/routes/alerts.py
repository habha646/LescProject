from flask import Blueprint, render_template

from .. import repository as repo

bp = Blueprint("alerts", __name__, url_prefix="/alertes")


@bp.route("/")
def index():
    return render_template("alerts.html", alerts=repo.list_alerts(limit=100))
