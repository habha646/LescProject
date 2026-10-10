"""API JSON utilisée par la console (la page principale, en JavaScript).

SÉCURITÉ — protection CSRF par en-tête personnalisé :
L'appli écoute sur 127.0.0.1. N'importe quel site web ouvert dans ton navigateur pourrait
essayer d'envoyer une requête POST vers http://127.0.0.1:5000/api/mail à ta place
(attaque CSRF, « Cross-Site Request Forgery »). Un site étranger peut envoyer un simple
formulaire, mais il NE PEUT PAS ajouter un en-tête personnalisé comme `X-Sentinelle`
sans que le navigateur demande d'abord l'autorisation au serveur (requête « preflight » CORS).
Notre serveur ne donne jamais cette autorisation, donc la requête piégée est bloquée.
Conclusion : toute requête qui modifie quelque chose doit porter cet en-tête.
"""
from __future__ import annotations

from flask import Blueprint, abort, current_app, jsonify, request

from .. import repository as repo
from ..db import get_db
from ..modules.mail import autotest
from ..services import analyze_and_store

bp = Blueprint("api", __name__, url_prefix="/api")

CSRF_HEADER = "X-Sentinelle"


@bp.before_request
def _require_custom_header():
    if request.method != "GET" and request.headers.get(CSRF_HEADER) != "1":
        abort(403)


@bp.get("/etat")
def etat():
    return jsonify({"counts": repo.counts(), "analyses": repo.list_analyses(limit=10)})


@bp.post("/mail")
def mail():
    f = request.files.get("eml_file")
    if not f or not f.filename:
        return jsonify({"error": "Aucun fichier reçu."}), 400
    if not f.filename.lower().endswith(".eml"):
        return jsonify({"error": "Seuls les fichiers .eml sont acceptés."}), 400
    verdict = analyze_and_store(f.read())
    data = verdict.to_dict()
    data["filename"] = f.filename
    data["counts"] = repo.counts()
    return jsonify(data)


# ---------- Écran de démarrage : de VRAIS contrôles ----------

@bp.get("/demarrage/base")
def demarrage_base():
    integrite = get_db().execute("PRAGMA quick_check").fetchone()[0]   # SQLite vérifie ses propres fichiers
    counts = repo.counts()
    return jsonify({
        "ok": integrite == "ok",
        "detail": f"Base SQLite : {integrite}",
        "lines": [f"{counts['total']} analyse(s) de mail enregistrée(s)"],
    })


@bp.get("/demarrage/moteur-mail")
def demarrage_moteur_mail():
    samples = current_app.config["SAMPLES_DIR"]
    if not (samples / "phishing").is_dir():
        return jsonify({"ok": True, "warn": True, "detail": "Jeu d'essai absent, auto-test ignoré", "lines": []})
    r = autotest.run(samples)
    total = r["phishing_total"] + r["legit_total"]
    return jsonify({
        "ok": True,
        "warn": r["detected"] < 8 or r["false_positives"] > 1,   # objectif : >= 8/10 et <= 1 faux positif
        "detail": f"Moteur testé sur {total} mails d'essai",
        "lines": [f"Phishings détectés : {r['detected']}/{r['phishing_total']}",
                  f"Faux positifs : {r['false_positives']}/{r['legit_total']}"],
    })
