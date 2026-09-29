"""Explications en langage clair — à améliorer par Svetoslav.

Étape 1 (déjà faite) : textes prédéfinis (templates) — marchent partout, sans IA.
Étape 2 (TODO Svetoslav) : brancher un modèle local via Ollama.
    - installer Ollama et un petit modèle, lire leur documentation officielle pour l'appel HTTP local
    - construire un prompt court : (1) ce qui s'est passé, (2) pourquoi c'est un risque, (3) quoi faire
    - toujours mettre un délai maximum (timeout) et retomber sur le template si ça échoue
    - ATTENTION : un petit modèle peut se tromper avec assurance -> ne jamais lui faire inventer de faits;
      donne-lui uniquement les données de l'alerte et demande de reformuler.
"""
from ...models import Alert, MailVerdict

_MAIL_ADVICE = {
    "safe": "Rien d'inquiétant n'a été détecté, mais reste prudent avec les pièces jointes inattendues.",
    "suspect": "Ce mail présente des signes douteux. Ne clique sur rien et ne télécharge rien avant d'avoir "
               "vérifié auprès de l'expéditeur par un autre moyen (téléphone, par exemple).",
    "dangerous": "Ce mail est très probablement dangereux. Ne l'ouvre pas, ne clique sur aucun lien, "
                 "et supprime-le. Si tu as déjà cliqué, préviens quelqu'un de l'équipe.",
}


def explain_with_template(alert: Alert) -> str:
    if alert.source == "unknown_device":
        ip = alert.details.get("ip", "?")
        return (f"Un appareil que tu ne connais pas s'est connecté à ton réseau (adresse {ip}). "
                "Regarde si c'est un appareil à toi (téléphone d'un invité, nouvel objet connecté). "
                "Si ce n'est pas le cas, change le mot de passe wifi et préviens l'équipe.")
    return "Un comportement inhabituel a été détecté. Vérifie les détails ci-dessus."


def explain_mail_with_template(v: MailVerdict) -> str:
    return _MAIL_ADVICE.get(v.verdict, "Analyse impossible.")


def explain_with_llm(alert: Alert) -> str:
    raise NotImplementedError("TODO (Svetoslav) : appel au modèle local.")


def explain_mail_with_llm(v: MailVerdict) -> str:
    raise NotImplementedError("TODO (Svetoslav) : appel au modèle local.")
