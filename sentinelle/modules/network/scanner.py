"""VRAI SCAN RÉSEAU — à écrire par David.

Ce que tu dois faire : remplir la fonction `scan` ci-dessous.
Elle reçoit un sous-réseau (ex. "192.168.1.0/24") DÉJÀ validé par le garde-fou,
et retourne une liste de `Device`.

Pistes (à toi de choisir et d'expliquer ton choix à la défense — note-le dans docs/DECISIONS.md) :
  - lire la table ARP de la machine (rapide, simple, sans droits spéciaux)
  - envoyer un ping / une requête ARP sur le sous-réseau
  - utiliser nmap ou une bibliothèque Python (vérifie leur documentation et les droits nécessaires)

Pour tester sans risque : mets SENTINELLE_NETWORK_MODE=real et
SENTINELLE_ALLOWED_SUBNETS=<ton réseau de test> dans ton fichier .env.
"""
from ...models import Device


def scan(subnet: str) -> list[Device]:
    raise NotImplementedError("TODO (David) : implémenter le scan réseau réel.")
