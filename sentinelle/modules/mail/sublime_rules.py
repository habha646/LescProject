"""Règles de détection adaptées de Sublime Security, réécrites en Python.

D'OÙ ÇA VIENT
    Sublime Security publie ses règles de détection de phishing sous licence MIT :
    https://github.com/sublime-security/sublime-rules
    Elles sont écrites en MQL, le langage de leur plateforme. On ne peut pas les exécuter
    telles quelles : on les a donc RÉÉCRITES en Python, une par une. La logique est la leur,
    le code est le nôtre. Chaque règle garde son identifiant Sublime pour retrouver l'original.
    Licence MIT : on a le droit de réutiliser, à condition de citer la source (c'est fait ici).

POURQUOI CES RÈGLES-LÀ
    Sur 1 414 règles, environ 70 % ont besoin de choses que Sentinelle n'a pas : leur IA maison,
    l'historique des mails d'une entreprise, l'ouverture des archives, la visite des liens en
    direct, l'âge des domaines (WHOIS). On a gardé les règles qui marchent avec le mail SEUL.

COMMENT C'EST ORGANISÉ (comme chez Sublime)
    Chaque règle est une « fiche » : identifiant, nom, gravité, types d'attaque, techniques,
    et une fonction `check` qui regarde le mail. Si elle trouve l'indice, elle renvoie une
    phrase d'explication en français ; sinon elle renvoie None.
    La gravité donne les points de risque (voir POINTS). rules.py additionne tout.

POUR AJOUTER UNE RÈGLE
    1. Écris une fonction _xxx(m) -> str | None.
    2. Ajoute une fiche Rule(...) dans la liste SUBLIME_RULES en bas du fichier.
    3. Écris un test dans tests/test_sublime_rules.py (un mail qui déclenche, un qui ne déclenche pas).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from .parser import ParsedMail

SOURCE = "https://github.com/sublime-security/sublime-rules/blob/main/detection-rules/"

# Gravité Sublime -> points de risque Sentinelle (rappel : >= 20 suspect, >= 50 dangereux).
# Une règle « low » seule ne suffit pas à rendre un mail suspect : c'est un petit indice.
POINTS = {"low": 10, "medium": 20, "high": 40, "critical": 50}

# Fournisseurs de mail gratuits (Sublime utilise sa propre liste $free_email_providers,
# qui n'est pas publique sous cette forme : celle-ci est la nôtre, à compléter).
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.fr", "hotmail.com", "hotmail.fr",
    "live.com", "live.fr", "msn.com", "yahoo.com", "yahoo.fr", "ymail.com", "aol.com",
    "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.fr", "gmx.de", "web.de",
    "protonmail.com", "proton.me", "zoho.com", "yandex.com", "yandex.ru", "mail.ru",
    "laposte.net", "orange.fr", "free.fr", "sfr.fr", "wanadoo.fr", "tutanota.com",
}

# Listes d'adresses et de domaines d'escrocs observés par Sublime (empreintes SHA-256).
_IOC = json.loads((Path(__file__).with_name("sublime_ioc.json")).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Rule:
    id: str                     # identifiant de la règle chez Sublime
    file: str                   # nom du fichier .yml d'origine
    name: str                   # nom de la règle (en anglais, comme l'original)
    severity: str               # low | medium | high | critical
    attack_types: tuple         # ex. ("Credential Phishing",)
    techniques: tuple           # ex. ("Evasion", "Punycode")
    check: Callable[[ParsedMail], Optional[str]]

    @property
    def points(self) -> int:
        return POINTS[self.severity]

    @property
    def url(self) -> str:
        return SOURCE + self.file


# ---------- petits outils ----------

def _domain(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def _local_part(address: str) -> str:
    return address.rsplit("@", 1)[0].lower() if "@" in address else ""


def _root_domain(domain: str) -> str:
    """'mail.banque.co.uk' -> 'banque.co.uk', 'a.b.example.com' -> 'example.com'.

    Approximation : la vraie méthode utilise la « Public Suffix List » (des milliers de cas).
    On gère seulement les suffixes à deux niveaux les plus courants (co.uk, com.au...).
    """
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _url(link: str):
    try:
        return urlparse(link.strip())
    except ValueError:
        return None


def _host(link: str) -> str:
    u = _url(link)
    try:
        return (u.hostname or "").lower() if u else ""
    except ValueError:
        return ""


def _subdomain(host: str) -> str:
    """'login-.paypal.example.com' -> 'login-.paypal' (tout ce qui précède le domaine racine)."""
    root = _root_domain(host)
    return host[: -len(root) - 1] if host.endswith("." + root) else ""


def _decode_hex(text: str) -> str:
    try:
        return bytes.fromhex(text).decode("utf-8")
    except ValueError:
        return ""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------- les règles ----------
# Chaque fonction cite en commentaire la condition MQL d'origine, simplifiée.

def _punycode_sender(m: ParsedMail) -> Optional[str]:
    # MQL : strings.ilike(sender.email.domain.domain, "*xn--*")
    # « xn-- » = domaine écrit avec des lettres étrangères qui imitent des lettres normales
    # (ex. un « а » cyrillique à la place du « a » latin dans « pаypal.com »).
    if "xn--" in _domain(m.sender_email):
        return f"Le domaine de l'expéditeur ({_domain(m.sender_email)}) utilise des lettres déguisées (punycode)."
    return None


def _punycode_link(m: ParsedMail) -> Optional[str]:
    # MQL : any(body.links, strings.starts_with(.href_url.domain.domain, "xn--") ou punycode non nul)
    for link in m.link_urls:
        host = _host(link)
        if any(label.startswith("xn--") for label in host.split(".")):
            return f"Un lien mène vers un domaine aux lettres déguisées (punycode) : {host}"
    return None


def _rtlo_attachment(m: ParsedMail) -> Optional[str]:
    # MQL : regex.icontains(.file_name, '\x{202E}', '\x{202D}')
    # U+202E retourne l'affichage du texte : « facture‮fdp.exe » s'affiche « factureexe.pdf ».
    for a in m.attachment_info:
        if "‮" in a["name"] or "‭" in a["name"]:
            return "Le nom d'une pièce jointe contient un caractère qui inverse l'affichage pour cacher sa vraie extension."
    return None


def _tar_is_rar(m: ParsedMail) -> Optional[str]:
    # MQL : .file_extension =~ "tar" and .file_type =~ "rar"
    for a in m.attachment_info:
        if a["name"].lower().endswith(".tar") and a["file_type"] == "rar":
            return f"La pièce jointe {a['name']} se dit .tar mais c'est en réalité une archive RAR (nom trompeur)."
    return None


_SMUGGLING_PATTERNS = [
    re.compile(r"document.{0,10}write.{0,10}atob", re.I),
    re.compile(r"=.?atob.*;", re.I),
    re.compile(r"atob.atob", re.I),
    re.compile(r"\{src: atob", re.I),
    re.compile(r"eval.atob", re.I),
    re.compile(r"atob\(.0x", re.I),
    re.compile(r"'at'\+'ob'", re.I),
    re.compile(r"ato\\u0062", re.I),
    re.compile(r"document.*insertAdjacentHTML.*atob", re.I | re.S),
]


def _html_smuggling(m: ParsedMail) -> Optional[str]:
    # Adapté de attachment_html_smuggling_atob.yml. Sublime ouvre aussi les archives et mesure
    # l'entropie (le « désordre » du contenu) : on ne fait que la partie recherche de motifs,
    # sur les pièces jointes HTML/SVG. atob() décode du base64 : on s'en sert pour fabriquer
    # un fichier piégé DANS le navigateur, sans qu'il passe par l'antivirus de la messagerie.
    for a in m.attachment_info:
        if a["text"] and any(p.search(a["text"]) for p in _SMUGGLING_PATTERNS):
            return f"La pièce jointe {a['name']} contient du code qui fabrique un fichier caché (HTML smuggling)."
    return None


def _fake_in_reply_to(m: ParsedMail) -> Optional[str]:
    # MQL : in_reply_to non nul, objet sans RE:/TR:, pas d'ancien fil, au moins 2 « * »
    # dans la partie locale de l'expéditeur.
    subject = m.subject.strip().lower()
    is_reply = subject.startswith(("re:", "re :", "tr:", "fw:", "fwd:"))
    has_thread = "-----original message-----" in m.body_text.lower() or "a écrit :" in m.body_text.lower()
    if m.in_reply_to and not is_reply and not has_thread and _local_part(m.sender_email).count("*") >= 2:
        return "Le mail se fait passer pour une réponse (In-Reply-To) sans conversation précédente, depuis une adresse bizarre."
    return None


def _freemail_reply_to_other_freemail(m: ParsedMail) -> Optional[str]:
    # MQL : expéditeur chez un webmail gratuit, Reply-To chez un AUTRE webmail gratuit.
    sender_root = _root_domain(_domain(m.sender_email))
    if sender_root not in FREE_EMAIL_PROVIDERS:
        return None
    for addr in m.reply_to_emails:
        root = _root_domain(_domain(addr))
        if root in FREE_EMAIL_PROVIDERS and root != sender_root and root != "googlegroups.com":
            return f"Envoyé depuis {sender_root} mais les réponses partent vers {root} : deux webmails gratuits différents."
    return None


_ZERO_WIDTH = re.compile("[​-‏­﻿⁠]")


def _zero_width_stuffing(m: ParsedMail) -> Optional[str]:
    # MQL : (liens ou pièces jointes) et >= 10 caractères invisibles dans l'objet ou le nom affiché.
    # Ces caractères invisibles cassent les mots pour tromper les filtres (« u​r​g​e​n​t »).
    if not (m.link_urls or m.attachment_info):
        return None
    if any(len(_ZERO_WIDTH.findall(t)) >= 10 for t in (m.subject, m.sender_name)):
        return "L'objet ou le nom de l'expéditeur est truffé de caractères invisibles pour tromper les filtres."
    return None


_TAG_CHARS = "[\U000E0020-\U000E007E]"


def _unicode_tag_chars(m: ParsedMail) -> Optional[str]:
    # MQL : > 10 « tag characters » Unicode, glissés entre des lettres ou en bloc de 10+.
    for text in (m.subject, m.body_text):
        if len(re.findall(_TAG_CHARS, text)) > 10 and (
            re.search("[A-Za-z0-9]" + _TAG_CHARS + "+[A-Za-z0-9]", text) or re.search(_TAG_CHARS + "{10,}", text)
        ):
            return "Le mail contient des caractères Unicode invisibles (« tag characters ») pour cacher du texte."
    return None


def _rtl_marks_in_link_text(m: ParsedMail) -> Optional[str]:
    # MQL : moins de 10 liens, et un texte de lien avec des lettres séparées par U+200F.
    if len(m.anchors) >= 10:
        return None
    for _href, text in m.anchors:
        if re.search("(?:[A-Za-z]‏){2,}[A-Za-z]", text):
            return "Le texte d'un lien est découpé par des caractères invisibles de sens d'écriture."
    return None


def _unicode_slashes(m: ParsedMail) -> Optional[str]:
    # MQL : une URL qui contient ⁄ (U+2044) ou ∕ (U+2215), des « faux » slashs.
    if re.search(r"https?://[^\s⁄∕]+(?:/[^\s⁄∕]+)*[⁄∕][^\s⁄∕]+", m.plain_raw, re.I) or any(
        "⁄" in u or "∕" in u for u in m.link_urls
    ):
        return "Une adresse web utilise de faux caractères « / » pour cacher le vrai domaine."
    return None


def _hidden_span_split_url(m: ParsedMail) -> Optional[str]:
    # MQL : 'https:/<span' + un <span display:none> qui coupe l'adresse en deux.
    raw = m.html_raw
    if "https:/<span" in raw.lower() and re.search(
        r"https:/<span[^>]{0,300}display:\s*none[^>]{0,300}>[A-Z0-9]{6,}\s*</span>/", raw, re.I
    ):
        return "Une adresse web est coupée par du texte caché pour échapper aux filtres."
    return None


def _css_clip_path(m: ParsedMail) -> Optional[str]:
    # MQL : un <div style="clip-path: inset(100%...)"> qui contient plus de 150 caractères.
    # clip-path: inset(100%) rend le bloc invisible : le filtre lit ce texte, l'humain non.
    for match in re.finditer(r"<div[^>]*clip-path:\s*inset\(\s*100%[^>]*>(.*?)</div>", m.html_raw, re.I | re.S):
        inner = re.sub(r"<[^>]+>", "", match.group(1))
        if len(inner.strip()) > 150:
            return "Le mail contient un long texte rendu invisible (CSS clip-path) pour tromper les filtres."
    return None


def _cve_2024_21413(m: ParsedMail) -> Optional[str]:
    # MQL : lien file:// suivi d'une extension puis « ! » (faille « MonikerLink » d'Outlook).
    for link in m.link_urls:
        if link.lower().startswith("file:") and re.search(r"\.[a-z]{2,4}(\.[a-z]{2,4})?!", link, re.I):
            return "Un lien exploite une faille connue d'Outlook (CVE-2024-21413, « MonikerLink »)."
    return None


def _cve_2023_5631(m: ParsedMail) -> Optional[str]:
    # MQL : pas de pièce jointe, et un SVG en base64 dans un <use href="data:image/svg+xml;base64,PHN2Zy...#">
    if not m.attachment_info and re.search(
        r'use href="data:image/svg\+xml;base64,PHN2Zy.*#', m.html_raw, re.I | re.S
    ):
        return "Le mail exploite une faille connue de Roundcube (CVE-2023-5631) via une image SVG piégée."
    return None


def _gophish_pixel(m: ParsedMail) -> Optional[str]:
    # MQL : image invisible <img alt="" style="display: none" src="..." + '/track?rid='
    # Gophish est un outil de simulation de phishing, souvent détourné par de vrais escrocs.
    raw = m.html_raw.lower()
    if ('img alt="" style="display: none" src="' in raw or "<img alt='' style='display: none' src='" in raw) and (
        "/track?rid=" in raw
    ):
        return "Le mail contient le traceur caché de Gophish, un outil de campagne de phishing."
    return None


def _recipient_hex_in_fragment(m: ParsedMail) -> Optional[str]:
    # MQL : strings.decode_hex(.href_url.fragment) == recipients.to[0].email.email
    # Le « fragment » est la partie après # dans une adresse web.
    if not m.to_emails:
        return None
    for link in m.link_urls:
        u = _url(link)
        if u and u.fragment and _decode_hex(u.fragment).lower() == m.to_emails[0]:
            return "Un lien contient ton adresse mail cachée (codée en hexadécimal) : le piège est personnalisé pour toi."
    return None


def _recipient_hex_in_subject(m: ParsedMail) -> Optional[str]:
    # MQL : un bloc hexadécimal de 20+ caractères dans l'objet qui, décodé, donne un destinataire.
    for block in re.findall(r"[0-9a-f]{20,}", m.subject, re.I):
        if _decode_hex(block).lower() in m.to_emails:
            return "L'objet contient ton adresse mail cachée en hexadécimal."
    return None


def _sender_built_from_recipient(m: ParsedMail) -> Optional[str]:
    # MQL : partie locale de l'expéditeur == « domaine-du-destinataire_nom-du-destinataire »,
    # alors que l'expéditeur est sur un autre domaine.
    if not m.to_emails:
        return None
    to = m.to_emails[0]
    sld = _root_domain(_domain(to)).split(".")[0]
    if _local_part(m.sender_email) == f"{sld}_{_local_part(to)}" and _root_domain(
        _domain(m.sender_email)
    ) != _root_domain(_domain(to)):
        return "L'adresse de l'expéditeur a été fabriquée à partir de TON adresse pour paraître familière."
    return None


def _subdomain_ends_with_hyphen(m: ParsedMail) -> Optional[str]:
    # MQL : un sous-domaine de lien qui finit par « - » (adresse fabriquée à la va-vite).
    for link in m.link_urls:
        if link.lower().startswith("mailto:"):
            continue
        if _subdomain(_host(link)).endswith("-"):
            return f"Un lien pointe vers une adresse mal formée (sous-domaine finissant par « - ») : {_host(link)}"
    return None


def _malformed_url_prefix(m: ParsedMail) -> Optional[str]:
    # MQL (simplifiée) : ':/\' dans un lien, ou 'https:\\' dans le texte. Ces fautes volontaires
    # empêchent les filtres de reconnaître le lien, mais le navigateur le corrige tout seul.
    # (On ignore la partie sur les liens Microsoft SafeLinks de l'original.)
    if any(":/\\" in u for u in m.link_urls) or re.search(r"https?:\\\\\S+", m.plain_raw, re.I):
        return "Un lien est volontairement mal écrit (« https:\\\\ ») pour échapper aux filtres."
    return None


def _malformed_outlook_mailer(m: ParsedMail) -> Optional[str]:
    # MQL : X-Mailer commence par « Microsoft Outlook, Build » mais n'a pas le format d'un vrai Outlook.
    if m.mailer.lower().startswith("microsoft outlook, build") and not re.match(
        r"Microsoft (?:Office )?Outlook, Build \d{1,2}\.0\.\d{4,5}", m.mailer, re.I
    ):
        return "Le mail prétend venir d'Outlook mais l'en-tête du logiciel est imité maladroitement."
    return None


def _underscore_dot_display(m: ParsedMail) -> Optional[str]:
    # MQL : texte de lien « https://... » qui contient « _com/ » au lieu de « .com/ ».
    for _href, text in m.anchors:
        if text.startswith("https://") and "_com/" in text and ".com/" not in text:
            return "Le texte d'un lien remplace « .com » par « _com » pour imiter une adresse sans en être une."
    return None


_ENGAGING_WORDS = [
    "kindly", "phone", "cell", "expedite", "urgent", "contact", "review", "confirm", "asap",
    "follow up", "nicely", "btc", "reply", "respond", "verify", "convenience", "response", "number",
    "mobile", "text", "request", "required", "important", "need", "quick", "sensitive", "reach", "action",
]
_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
_MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september",
           "october", "november", "december"]


def _gmail_engaging_display_name(m: ParsedMail) -> Optional[str]:
    # MQL : expéditeur @gmail.com, sans lien ni pièce jointe, et au moins 2 mots « engageants »
    # dans le NOM AFFICHÉ (ex. « Urgent - Please Reply »). Arnaque au « contacte-moi vite ».
    if _domain(m.sender_email) != "gmail.com" or m.attachment_info or m.link_urls:
        return None
    name = m.sender_name.lower()
    hits = sum(word in name for word in _ENGAGING_WORDS)
    hits += any(d in name for d in _DAYS) + any(mo in name for mo in _MONTHS)
    if hits >= 2:
        return f"Le nom affiché de l'expéditeur (« {m.sender_name} ») est une phrase qui pousse à répondre, depuis un Gmail."
    return None


def _ioc_sender(m: ParsedMail) -> Optional[str]:
    # MQL : hash.sha256(sender.email.email) in (...) ou hash.sha256(root_domain) in (...)
    # On compare des EMPREINTES : la liste ne révèle pas les adresses en clair.
    if m.sender_email and _sha256(m.sender_email) in _IOC["sender_emails"]:
        return "L'adresse de l'expéditeur figure sur la liste d'escrocs connus de Sublime Security."
    root = _root_domain(_domain(m.sender_email))
    if root and _sha256(root) in _IOC["sender_root_domains"]:
        return f"Le domaine de l'expéditeur ({root}) figure sur la liste d'escrocs connus de Sublime Security."
    return None


SUBLIME_RULES = [
    Rule("bc3d8db5-dc83-5b77-bee4-9cf62f32b6de", "punycode_sender_domain.yml", "Punycode sender domain",
         "high", ("Credential Phishing",), ("Evasion", "Punycode"), _punycode_sender),
    Rule("74b3698c-d75e-52db-9596-48af93817822", "link_contains_punycode_characters.yml",
         "Link to a domain with punycode characters", "medium", ("Credential Phishing",), ("Punycode",),
         _punycode_link),
    Rule("357c57a1-dd29-5ad8-ae2f-c4f4c6489575", "attachment_filename_with_unicode_rtlo.yml",
         "Attachment: Filename containing Unicode right-to-left override character", "high", ("Malware/Ransomware",),
         ("Evasion",), _rtlo_attachment),
    Rule("364a0ea6-8011-5de2-b4c5-5eff8134037a", "attachment_tar_with_rar_type.yml", "Attachment: TAR file with RAR type", "high",
         ("Malware/Ransomware",), ("Evasion",), _tar_is_rar),
    Rule("03fcac11-ffc9-5a9c-9e1e-c866e683b48e", "attachment_html_smuggling_atob.yml", "Attachment: HTML smuggling with atob (adapté)", "high",
         ("Credential Phishing", "Malware/Ransomware"), ("HTML smuggling", "Scripting"), _html_smuggling),
    Rule("89da670a-4b03-52f7-891c-48820bb2362a", "headers_reply_to_wildcard_sender.yml",
         "Headers: Fake in-reply-to with wildcard sender and missing thread context", "high", ("Spam",),
         ("Evasion", "Social engineering"), _fake_in_reply_to),
    Rule("fcd831d0-9e03-5c9a-aa2f-af37d3a8c156", "sender_freemail_replyto_different_freemail.yml",
         "Free email provider sender with mismatched provider reply-to", "medium", ("BEC/Fraud",),
         ("Free email provider",), _freemail_reply_to_other_freemail),
    Rule("9342c8f9-8384-5dfb-945f-4f4438e6f32d", "evasion_zero_width_char_stuffing.yml",
         "Evasion: Zero-width character stuffing in subject or sender name", "medium",
         ("Credential Phishing",), ("Evasion",), _zero_width_stuffing),
    Rule("45a895a6-b1ba-53d1-9116-7c3cf21c4e99", "evasion_unicode_tag_chars_not_attachment.yml",
         "Evasion: Suspicious use of Unicode tag characters", "medium", ("Credential Phishing",), ("Evasion",),
         _unicode_tag_chars),
    Rule("a45cfd4c-3690-51a8-96b8-fb4daab18eca", "link_display_text_excessive_right_to_left_marks.yml",
         "Link: Display text with excessive right-to-left mark characters", "low", ("Credential Phishing",),
         ("Evasion",), _rtl_marks_in_link_text),
    Rule("12069f5b-a774-53ba-8473-633291f71e84", "body_unicode_slashes_in_url.yml",
         "URL with Unicode U+2044 or U+2215 characters", "low", ("Credential Phishing",), ("Evasion",),
         _unicode_slashes),
    Rule("9c7f6db1-2e4e-50db-ab74-eaa29822189e", "link_hidden_span_split_url.yml", "Link: URL fragmented by hidden spans", "high",
         ("Credential Phishing",), ("Evasion",), _hidden_span_split_url),
    Rule("ca09550e-7f33-535c-a178-3455faa5143b", "body_css_clip_path.yml", "Body: CSS Hidden text via clip-path",
         "medium", ("Credential Phishing",), ("Evasion",), _css_clip_path),
    Rule("e8151426-6893-598b-a42c-6ab8c0d0621d", "link_cve_2024-21413.yml", "Link: CVE-2024-21413 Microsoft Outlook Remote Code Execution", "high",
         ("Malware/Ransomware",), ("Exploit",), _cve_2024_21413),
    Rule("8405d61b-4330-534e-b64c-f98ee15d8767", "body_cve_2023_5631.yml", "CVE-2023-5631 - Roundcube Webmail XSS via crafted SVG", "critical",
         ("Credential Phishing",), ("Exploit",), _cve_2023_5631),
    Rule("59915ceb-4d7c-56ba-a28e-ccda8d95b5e2", "gophish_abuse_pixel_tracking.yml", "Credential theft: Gophish abuse with hidden tracking image",
         "high", ("Credential Phishing",), ("Evasion",), _gophish_pixel),
    Rule("046ed6f2-4825-5b41-9410-630113920ba3", "link_rcpt_hex_encoded_fragment.yml",
         "Link: Hex-encoded recipient email in URL fragment", "medium", ("Credential Phishing",),
         ("Encryption", "Evasion"), _recipient_hex_in_fragment),
    Rule("310a5e51-1f39-5bfe-a448-f31bb3ac8913", "hex_encoded_rcpt_subject.yml",
         "Subject: Hex-encoded recipient address in subject", "medium", ("Credential Phishing",),
         ("Encryption", "Evasion"), _recipient_hex_in_subject),
    Rule("fce2ba42-17a2-5b84-8760-0a5e641f0bb8", "sender_local_part_built_from_recipient.yml",
         "Sender: Local part built from recipient domain and mailbox", "low", ("Credential Phishing",),
         ("Social engineering",), _sender_built_from_recipient),
    Rule("16fbcf85-be63-54c5-a36e-ce180f7499d1", "link_malfrom_subdomain_hyphen.yml",
         "Link: Malformed subdomain ending in hyphen", "low", ("Credential Phishing",), ("Evasion",),
         _subdomain_ends_with_hyphen),
    Rule("4e659d28-53fa-51ca-888d-a7cab1e4bcad", "malformed_url_prefix.yml", "Malformed URL prefix (simplifiée)",
         "high", ("Credential Phishing",), ("Evasion",), _malformed_url_prefix),
    Rule("b3318772-815b-56b4-970b-4bb793f7a6f4", "headers_malformed_mailer_string.yml",
         "Headers: Malformed Outlook mailer string", "medium", ("Credential Phishing", "Spam"),
         ("Spoofing",), _malformed_outlook_mailer),
    Rule("802edfc6-5031-59bb-831b-16d0772b2b96", "link_obfuscation_underscore_dot_substitution.yml",
         "Link: URL using underscore-dot substitution in display text", "medium", ("Credential Phishing",),
         ("Evasion",), _underscore_dot_display),
    Rule("82ca0ff1-e823-5930-aa2d-7d2b572a528b", "sender_suspicious_display_name_from_gmail_domain.yml",
         "Suspicious display name: Gmail sender with engaging language", "low", ("BEC/Fraud",),
         ("Free email provider", "Social engineering"), _gmail_engaging_display_name),
    Rule("b1c2d3e4-f5a6-4b8c-9d0e-f1a2b3c4d5e6", "observed_malicious_sender_emails.yml + observed_malicious_sender_root_domains.yml",
         "Observed IOC: Malicious sender emails and root domains", "high", ("BEC/Fraud", "Credential Phishing"),
         ("Threat intelligence",), _ioc_sender),
]


def run_sublime_rules(m: ParsedMail) -> list[tuple[Rule, str]]:
    """Lance toutes les règles. Renvoie la liste (règle, explication) de celles qui ont trouvé un indice.

    Une règle qui plante (mail très bizarre) est ignorée : un outil de sécurité ne doit jamais
    s'arrêter à cause d'une donnée envoyée par l'attaquant.
    """
    hits = []
    for rule in SUBLIME_RULES:
        try:
            reason = rule.check(m)
        except Exception:
            continue
        if reason:
            hits.append((rule, reason))
    return hits
