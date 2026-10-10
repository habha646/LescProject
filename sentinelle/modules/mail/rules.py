"""Règles de notation d'un mail — simples, lisibles, faciles à expliquer à la défense.

Chaque règle regarde UN indice de phishing. Si elle le trouve, elle ajoute des points
de risque et une raison en français. Le score total (0 à 100) donne le verdict :
    >= 50 : dangereux      >= 20 : suspect      sinon : sûr

Aucun indice seul n'est une preuve. C'est l'ADDITION de plusieurs indices qui rend
un mail dangereux : c'est pour ça que chaque règle donne peu de points.

Pour ajouter une règle : écris une fonction _check_xxx(m, reasons) -> int,
puis ajoute-la dans la liste RULES en bas du fichier.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import urlparse

from .parser import ParsedMail
from ...models import MailVerdict

# Conseil affiché à l'utilisateur selon le verdict
ADVICE = {
    "safe": "Rien d'inquiétant n'a été détecté, mais reste prudent avec les pièces jointes inattendues.",
    "suspect": "Ce mail présente des signes douteux. Ne clique sur rien et ne télécharge rien avant d'avoir "
               "vérifié auprès de l'expéditeur par un autre moyen (téléphone, par exemple).",
    "dangerous": "Ce mail est très probablement dangereux. Ne l'ouvre pas, ne clique sur aucun lien, "
                 "et supprime-le. Si tu as déjà cliqué, préviens quelqu'un de l'équipe.",
}

# Fichiers qui peuvent lancer un programme ou une page piégée quand on les ouvre.
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".jar", ".msi",
                        ".ps1", ".hta", ".lnk", ".iso", ".img", ".html", ".htm"}

# Services qui raccourcissent une adresse : ils cachent la vraie destination du lien.
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
                  "rebrand.ly", "shorturl.at", "tiny.cc"}

# Écrits SANS accents : le texte du mail est lui aussi mis sans accents avant la comparaison.
URGENT_WORDS = ["urgent", "immediatement", "votre compte sera ferme", "cliquez ici",
                "verifiez votre compte", "dernier avertissement", "sous 24h", "sans reponse de votre part",
                "confidentiel", "n'en parle a personne"]

# Ce qu'une banque ou une entreprise sérieuse ne demande JAMAIS par mail.
SENSITIVE_WORDS = ["code d'acces", "code secret", "numero client", "date de naissance",
                   "carte bancaire", "numero de carte", "cryptogramme", "virement", "rib"]


# ---------- petits outils ----------

def _normalise(text: str) -> str:
    """Minuscules et sans accents : « Immédiatement » et « immediatement » sont pareils."""
    text = unicodedata.normalize("NFD", text.lower())
    return "".join(c for c in text if unicodedata.category(c) != "Mn")


def _domain_of_address(address: str) -> str:
    """'"Banque" <noreply@banque.example>' -> 'banque.example'."""
    _name, email_only = parseaddr(address)
    return email_only.rsplit("@", 1)[1].lower() if "@" in email_only else ""


def _host_of_url(url: str) -> str:
    """'https://www.site.fr/page' -> 'www.site.fr'."""
    try:
        return (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _without_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------- les règles ----------

def _check_auth_headers(m: ParsedMail, reasons: list[str]) -> int:
    """SPF/DKIM : le serveur qui a reçu le mail a vérifié si l'expéditeur avait le droit
    d'envoyer au nom de ce domaine. « fail » = probablement une usurpation."""
    auth = (m.headers.get("authentication_results") or "").lower()
    if "spf=fail" in auth or "dkim=fail" in auth:
        reasons.append("L'authentification de l'expéditeur (SPF/DKIM) a échoué : l'adresse pourrait être usurpée.")
        return 35
    return 0


def _check_attachments(m: ParsedMail, reasons: list[str]) -> int:
    """Une pièce jointe qui s'exécute (ou une page web en pièce jointe) peut installer
    un virus ou afficher une fausse page de connexion. On regarde la DERNIÈRE extension :
    « releve.pdf.exe » est un .exe déguisé en PDF."""
    score = 0
    for name in m.attachments:
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            score += 40
            reasons.append(f"Pièce jointe d'un type à risque : {name}")
    return score


def _check_reply_to(m: ParsedMail, reasons: list[str]) -> int:
    """Le mail dit venir de A, mais ta réponse partira chez B : l'escroc reçoit tes réponses.
    On compare les DOMAINES (pas les adresses) : un club qui répond depuis une autre adresse
    de son propre domaine, c'est normal."""
    reply_to = m.headers.get("reply_to") or ""
    if not reply_to:
        return 0
    domain_from, domain_reply = _domain_of_address(m.from_addr), _domain_of_address(reply_to)
    if domain_reply and domain_reply != domain_from:
        reasons.append(f"Les réponses partent vers un autre domaine ({domain_reply}) "
                       f"que celui de l'expéditeur ({domain_from}).")
        return 30
    return 0


def _check_links(m: ParsedMail, reasons: list[str]) -> int:
    """Indices dans l'adresse des liens. Chaque type d'indice ne compte qu'une fois."""
    found: dict[str, int] = {}

    def flag(kind: str, points: int, reason: str) -> None:
        if kind not in found:          # on ne compte chaque type d'indice qu'une fois
            found[kind] = points
            reasons.append(reason)

    for link in m.links:
        host = _host_of_url(link)
        if not host:
            continue
        if _is_ip(host):
            # Les vrais sites ont un nom ; un lien vers des chiffres sert à éviter d'être reconnu.
            flag("ip", 30, f"Lien vers une adresse IP au lieu d'un nom de site : {link}")
        elif _without_www(host) in URL_SHORTENERS:
            flag("short", 20, f"Lien raccourci qui cache sa vraie destination : {link}")
        elif "xn--" in host or "@" in link or host.count(".") >= 4:
            # xn-- = lettres étrangères qui imitent des lettres normales ; beaucoup de points =
            # « ma-banque.fr.site-pirate.test » pour que le début ressemble au vrai site.
            flag("odd", 20, f"Adresse de lien trompeuse : {link}")
    return sum(found.values())


def _check_link_text(m: ParsedMail, reasons: list[str]) -> int:
    """En HTML, le texte affiché d'un lien peut être une adresse… différente de la vraie.
    Ex. on lit « https://ma-banque.fr » mais le clic mène à « site-pirate.test »."""
    for href, text in m.anchors:
        shown = text.lower()
        if shown.startswith("www."):
            shown_host = _host_of_url("http://" + text)
        elif shown.startswith(("http://", "https://")):
            shown_host = _host_of_url(text)
        else:
            continue                   # le texte n'est pas une adresse (« Cliquez ici ») : rien à comparer
        real_host = _host_of_url(href)
        if shown_host and real_host and _without_www(shown_host) != _without_www(real_host):
            reasons.append(f"Le lien affiche « {shown_host} » mais mène en réalité à « {real_host} ».")
            return 40
    return 0


def _check_urgency(m: ParsedMail, reasons: list[str]) -> int:
    """Pression du temps ou du secret : on veut te faire agir avant que tu réfléchisses."""
    text = _normalise(m.subject + " " + m.body_text)
    if any(word in text for word in URGENT_WORDS):
        reasons.append("Le message pousse à agir vite ou en secret, sans réfléchir (technique classique de phishing).")
        return 15
    return 0


def _check_sensitive_request(m: ParsedMail, reasons: list[str]) -> int:
    """Demande de codes, de données bancaires ou de virement : une organisation sérieuse
    ne le fait jamais par mail. \\b = début/fin de mot, pour ne pas trouver « rib » dans « attribut »."""
    text = _normalise(m.subject + " " + m.body_text)
    for word in SENSITIVE_WORDS:
        if re.search(r"\b" + re.escape(word) + r"\b", text):
            reasons.append(f"Le mail parle d'informations sensibles ou d'argent (« {word} ») : "
                           "ne les donne jamais par mail.")
            return 20
    return 0


RULES = [
    _check_auth_headers,
    _check_attachments,
    _check_reply_to,
    _check_links,
    _check_link_text,
    _check_urgency,
    _check_sensitive_request,
]


def score_mail(m: ParsedMail) -> MailVerdict:
    reasons: list[str] = []
    score = min(sum(rule(m, reasons) for rule in RULES), 100)

    if score >= 50:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspect"
    else:
        verdict = "safe"
        if not reasons:
            reasons.append("Aucun signal de risque détecté par nos règles actuelles.")

    return MailVerdict(verdict=verdict, score=score, reasons=reasons,
                       links=m.links, attachments=m.attachments, explanation=ADVICE[verdict])
