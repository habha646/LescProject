"""Module IA — propriétaire : Svetoslav.

CONTRATS (ne change pas les signatures) :
    explain(alert: Alert) -> str
    explain_mail(verdict: MailVerdict) -> str

Règles :
  - Ne JAMAIS lever d'exception : en cas de problème, retourne le texte de secours.
  - Toujours en français simple, sans jargon, avec "quoi faire" à la fin.
  - L'IA EXPLIQUE et PROPOSE. Elle ne décide et n'exécute jamais une action seule.
Le produit fonctionne sans IA (mode "template") : ton travail améliore, il ne bloque personne.
"""
from flask import current_app

from . import explainer
from ...models import Alert, MailVerdict


def explain(alert: Alert) -> str:
    try:
        if current_app.config["AI_MODE"] == "ollama":
            return explainer.explain_with_llm(alert)
    except Exception:
        pass  # on retombe sur le texte prédéfini
    return explainer.explain_with_template(alert)


def explain_mail(verdict: MailVerdict) -> str:
    try:
        if current_app.config["AI_MODE"] == "ollama":
            return explainer.explain_mail_with_llm(verdict)
    except Exception:
        pass
    return explainer.explain_mail_with_template(verdict)
