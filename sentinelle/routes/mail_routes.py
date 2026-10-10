from flask import Blueprint, flash, render_template, request

from .. import repository as repo
from ..services import analyze_and_store

bp = Blueprint("mail", __name__, url_prefix="/mail")


@bp.route("/", methods=["GET", "POST"])
def index():
    verdict = None
    if request.method == "POST":
        f = request.files.get("eml_file")
        if not f or not f.filename:
            flash("Choisis d'abord un fichier .eml.", "warning")
        else:
            verdict = analyze_and_store(f.read())

    return render_template("mail.html", verdict=verdict, history=repo.list_analyses(limit=10))
