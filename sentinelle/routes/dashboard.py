from flask import Blueprint, render_template

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    # La console charge ses données elle-même via /api/... (voir static/console.js)
    return render_template("console.html")
