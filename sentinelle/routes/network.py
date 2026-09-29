from flask import Blueprint, flash, redirect, render_template, url_for

from .. import repository as repo
from ..models import Alert
from ..modules import ai
from ..modules.network import scan_devices

bp = Blueprint("network", __name__, url_prefix="/reseau")


@bp.route("/")
def index():
    return render_template("network.html", devices=repo.list_devices())


@bp.route("/scanner", methods=["POST"])
def run_scan():
    try:
        devices = scan_devices()
    except PermissionError as e:
        flash(str(e), "danger")
        return redirect(url_for("network.index"))
    except NotImplementedError:
        flash("Le scan réel n'est pas encore implémenté (module de David).", "warning")
        return redirect(url_for("network.index"))

    baseline = repo.counts()["devices"] == 0
    new_devices = repo.upsert_devices(devices, baseline=baseline)

    for d in new_devices:
        alert = Alert(
            source="unknown_device",
            severity="warning",
            title=f"Nouvel appareil détecté : {d.ip}",
            details={"ip": d.ip, "mac": d.mac, "hostname": d.hostname},
            dedupe_key=f"unknown_device:{d.mac}",
        )
        alert.explanation = ai.explain(alert)
        repo.add_alert(alert)

    if new_devices:
        flash(f"{len(new_devices)} nouvel(aux) appareil(s) détecté(s).", "warning")
    else:
        flash("Scan terminé, rien de nouveau.", "info")
    return redirect(url_for("network.index"))


@bp.route("/connu/<mac>", methods=["POST"])
def mark_known(mac):
    repo.mark_known(mac)
    return redirect(url_for("network.index"))
