"""Lecture du texte renvoyé par la commande `arp -a` (Windows).

Cette fonction ne lance aucune commande : elle lit seulement du texte.
"""

import ipaddress
import subprocess

MAC_BROADCAST = "ff-ff-ff-ff-ff-ff"


def parse_arp_output(texte):
    appareils = []
    for ligne in texte.splitlines():
        morceaux = ligne.split()
        if len(morceaux) != 3:
            continue
        ip, mac, type_ = morceaux
        mac = mac.lower()
        try:
            adresse = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if len(mac.split("-")) != 6:
            continue
        if adresse.is_multicast or mac == MAC_BROADCAST:
            continue
        appareils.append({"ip": ip, "mac": mac, "type": type_.lower()})
    return appareils

def lire_table_arp():
    """Lance `arp -a` et renvoie la liste des appareils. Renvoie [] si la commande échoue."""
    try:
        resultat = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if resultat.returncode != 0:
        return []
    return parse_arp_output(resultat.stdout)