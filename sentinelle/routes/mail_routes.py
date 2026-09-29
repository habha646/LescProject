import hashlib

from flask import Blueprint, flash, render_template, request

from .. import repository as repo
from ..modules import ai
from ..modules.mail import analyze_eml

bp = Blueprint("mail", __name__, url_prefix="/mail")


@bp.route("/", methods=["GET", "POST"])
def index():
    verdict = None
    if request.method == "POST":
        f = request.files.get("eml_file")
        if not f or not f.filename:
            flash("Choisis d'abord un fichier .eml.", "warning")
        else:
            raw = f.read()
            verdict = analyze_eml(raw)
            verdict.explanation = ai.explain_mail(verdict)
            # RGPD : on garde seulement l'empreinte (sha256), jamais le contenu du mail
            digest = hashlib.sha256(raw).hexdigest()
            repo.add_analysis(digest, verdict.verdict, verdict.score, verdict.reasons)

    return render_template("mail.html", verdict=verdict, history=repo.list_analyses(limit=10))
