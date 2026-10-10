"""Pages pas encore construites. On les affiche quand même pour montrer où ira chaque module."""
from flask import Blueprint, render_template

bp = Blueprint("construction", __name__)


@bp.route("/reseau/")
def network():
    return render_template("construction.html", zone="Réseau",
                           description="Surveillance des appareils connectés à ton réseau.")


@bp.route("/alertes/")
def alerts():
    return render_template("construction.html", zone="Alertes",
                           description="Historique de tout ce que Sentinelle a remarqué.")


@bp.route("/ia/")
def ai():
    return render_template("construction.html", zone="Assistant IA",
                           description="Un assistant qui explique chaque risque en langage simple.")
