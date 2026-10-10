"""Auto-test du moteur mail sur le jeu d'essai samples/phishing et samples/legit.

Utilisé à deux endroits :
  - tools/evaluate.py (en ligne de commande, pour mesurer nos progrès) ;
  - l'écran de démarrage (pour vérifier que le moteur marche vraiment avant de s'en servir).
"""
from __future__ import annotations

from pathlib import Path

from . import analyze_eml


def run(samples_dir: Path) -> dict:
    """Analyse tous les mails d'essai. Un mail est « signalé » si son verdict n'est pas « safe »."""
    results = {"phishing": [], "legit": []}
    for category in results:
        for path in sorted((samples_dir / category).glob("*.eml")):
            verdict = analyze_eml(path.read_bytes())
            results[category].append({"name": path.name, "verdict": verdict})

    detected = sum(r["verdict"].verdict != "safe" for r in results["phishing"])
    false_positives = sum(r["verdict"].verdict != "safe" for r in results["legit"])
    return {
        "results": results,
        "phishing_total": len(results["phishing"]),
        "detected": detected,
        "legit_total": len(results["legit"]),
        "false_positives": false_positives,
    }
