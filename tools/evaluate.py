"""Mesure la qualité de la détection mail sur le jeu de test samples/.

Usage (depuis la racine du projet) :
    python tools/evaluate.py        (ajoute -v pour voir les raisons)

Un mail est "signalé" si son verdict est "suspect" ou "dangerous".
Objectif SMART phase 1 : >= 8/10 phishings signalés, <= 1/10 faux positif.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))   # pour pouvoir importer le paquet sentinelle

from sentinelle.modules.mail import autotest  # noqa: E402

OBJECTIF_DETECTION = 8
OBJECTIF_FAUX_POSITIFS_MAX = 1


def _affiche(titre: str, resultats: list[dict], signal_attendu: bool) -> None:
    print(f"\n=== {titre} ===")
    for r in resultats:
        v = r["verdict"]
        ok = (v.verdict != "safe") == signal_attendu
        marque = "OK  " if ok else "RATE"
        print(f"[{marque}] {r['name']:<35} {v.verdict:<10} score={v.score}")
        if "-v" in sys.argv:
            for raison in v.reasons:
                print(f"         - {raison}")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")   # accents lisibles dans la console Windows
    rapport = autotest.run(ROOT / "samples")

    _affiche("PHISHING (doivent être signalés)", rapport["results"]["phishing"], True)
    _affiche("LÉGITIMES (ne doivent pas être signalés)", rapport["results"]["legit"], False)

    detectes, faux_positifs = rapport["detected"], rapport["false_positives"]
    print("\n=== RÉSULTAT ===")
    print(f"Phishings détectés : {detectes}/{rapport['phishing_total']}  (objectif >= {OBJECTIF_DETECTION})")
    print(f"Faux positifs      : {faux_positifs}/{rapport['legit_total']}  (objectif <= {OBJECTIF_FAUX_POSITIFS_MAX})")

    atteint = detectes >= OBJECTIF_DETECTION and faux_positifs <= OBJECTIF_FAUX_POSITIFS_MAX
    print("Objectif atteint." if atteint else "Objectif pas encore atteint.")
    return 0 if atteint else 1


if __name__ == "__main__":
    raise SystemExit(main())
