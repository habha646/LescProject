"""Module RÉSEAU — propriétaire : David.

CONTRAT (ne change pas la signature) :
    scan_devices() -> list[Device]

Tu n'as qu'UNE chose à faire : implémenter `scan(subnet)` dans scanner.py.
Le reste (garde-fou d'éthique, mode simulé, enregistrement, alertes, affichage) est déjà branché.
"""
from flask import current_app

from ..network import fake, guard
from ...models import Device


def scan_devices() -> list[Device]:
    mode = current_app.config["NETWORK_MODE"]
    if mode == "fake":
        return fake.scan()
    if mode == "real":
        from . import scanner
        devices: list[Device] = []
        for subnet in current_app.config["ALLOWED_SUBNETS"]:
            guard.ensure_allowed(subnet, current_app.config["ALLOWED_SUBNETS"])
            devices.extend(scanner.scan(subnet))
        if not current_app.config["ALLOWED_SUBNETS"]:
            raise PermissionError("Aucun sous-réseau autorisé (SENTINELLE_ALLOWED_SUBNETS est vide).")
        return devices
    raise ValueError(f"Mode réseau inconnu : {mode}")
