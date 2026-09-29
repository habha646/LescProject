"""Règles de notation d'un mail — simples, lisibles, faciles à expliquer à la défense.

Chaque règle ajoute des points de risque (0-100) et une raison en français.
Facile à étendre : ajoute une fonction _check_xxx et appelle-la dans score_mail.
"""
from __future__ import annotations

from .parser import ParsedMail
from ...models import MailVerdict

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".js", ".vbs", ".jar", ".cmd", ".msi"}
URGENT_WORDS = ["urgent", "immédiatement", "votre compte sera fermé", "cliquez ici",
                "vérifiez votre compte", "dernier avertissement"]


def _check_auth_headers(m: ParsedMail, reasons: list[str]) -> int:
    score = 0
    auth = (m.headers.get("authentication_results") or "").lower()
    if "spf=fail" in auth or "dkim=fail" in auth:
        score += 35
        reasons.append("L'authentification de l'expéditeur (SPF/DKIM) a échoué : l'adresse pourrait être usurpée.")
    return score


def _check_attachments(m: ParsedMail, reasons: list[str]) -> int:
    score = 0
    for name in m.attachments:
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            score += 40
            reasons.append(f"Pièce jointe d'un type à risque : {name}")
    return score


def _check_links(m: ParsedMail, reasons: list[str]) -> int:
    score = 0
    for link in m.links:
        if any(c in link for c in ["@", "xn--"]) or link.count(".") >= 5:
            score += 20
            reasons.append(f"Lien à l'aspect suspect : {link}")
    return score


def _check_urgency(m: ParsedMail, reasons: list[str]) -> int:
    text = (m.subject + " " + m.body_text).lower()
    for word in URGENT_WORDS:
        if word in text:
            reasons.append("Le message pousse à agir vite sans réfléchir (technique classique de phishing).")
            return 15
    return 0


def score_mail(m: ParsedMail) -> MailVerdict:
    reasons: list[str] = []
    score = 0
    score += _check_auth_headers(m, reasons)
    score += _check_attachments(m, reasons)
    score += _check_links(m, reasons)
    score += _check_urgency(m, reasons)
    score = min(score, 100)

    if score >= 50:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspect"
    else:
        verdict = "safe"
        if not reasons:
            reasons.append("Aucun signal de risque détecté par nos règles actuelles.")

    return MailVerdict(verdict=verdict, score=score, reasons=reasons,
                        links=m.links, attachments=m.attachments)
