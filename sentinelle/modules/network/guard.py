"""Garde-fou éthique/légal : on ne scanne QUE un réseau explicitement autorisé.

Scanner un réseau qui n'est pas le tien (ou sans accord) peut être illégal.
Ce fichier est un choix d'équipe : ne pas le contourner.
"""
import ipaddress


def ensure_allowed(subnet: str, allowed: list[str]) -> None:
    target = ipaddress.ip_network(subnet, strict=False)
    for a in allowed:
        if target.subnet_of(ipaddress.ip_network(a, strict=False)):
            return
    raise PermissionError(f"Scan refusé : {subnet} n'est pas dans les sous-réseaux autorisés.")
