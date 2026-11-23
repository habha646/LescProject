"""Lit un fichier .eml et en extrait les informations utiles.

RGPD : on ne stocke JAMAIS le corps du mail ni les pièces jointes elles-mêmes,
seulement ce qui sert à l'analyse (métadonnées, liens, noms de fichiers).

Un mail peut contenir du texte simple (text/plain), du HTML (text/html), ou les deux.
Les phishings sont presque toujours en HTML, car le HTML permet de CACHER la vraie
adresse d'un lien derrière un texte trompeur :
    <a href="http://site-pirate.test">https://ma-banque.fr</a>
On lit donc aussi le HTML, et on garde chaque lien avec le texte affiché.
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

_LINK_RE = re.compile(r'https?://[^\s"\'<>]+')


@dataclass
class ParsedMail:
    subject: str = ""
    from_addr: str = ""
    headers: dict = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    anchors: list[tuple[str, str]] = field(default_factory=list)   # (vraie adresse, texte affiché)
    attachments: list[str] = field(default_factory=list)            # noms de fichiers seulement
    body_text: str = ""   # utilisé UNIQUEMENT pendant l'analyse, jamais enregistré en base

    # --- Champs ajoutés pour les règles inspirées de Sublime Security (sublime_rules.py) ---
    # Comme body_text : utilisés pendant l'analyse, JAMAIS enregistrés en base (RGPD).
    sender_name: str = ""        # nom affiché de l'expéditeur, décodé (« Banque Lumière »)
    sender_email: str = ""       # adresse de l'expéditeur, en minuscules
    reply_to_emails: list[str] = field(default_factory=list)
    to_emails: list[str] = field(default_factory=list)              # destinataires (la victime)
    in_reply_to: str = ""        # en-tête In-Reply-To : « ce mail répond à… »
    mailer: str = ""             # en-tête X-Mailer : le logiciel qui a envoyé le mail
    html_raw: str = ""           # le HTML brut, pour chercher des pièges cachés dans le code
    plain_raw: str = ""          # le texte simple brut
    link_urls: list[str] = field(default_factory=list)              # TOUS les liens, même file:// ou mailto:
    attachment_info: list[dict] = field(default_factory=list)       # nom, type annoncé, vrai type, texte HTML


class _HTMLReader(HTMLParser):
    """Lit le HTML : récupère le texte visible et chaque lien <a href="...">texte</a>."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._anchor_text).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _decode(part: Message) -> str:
    try:
        return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
    except Exception:
        return str(part.get_payload())


def _decode_header(value) -> str:
    """'=?UTF-8?B?VXJnZW50?=' -> 'Urgent'. Sans encodage, le texte reste tel quel.

    SECURITE : pour l'OBJET seulement, jamais avant parseaddr(). Decode, un nom affiche
    peut contenir une fausse adresse qui trompe parseaddr et cache celle de l'escroc.
    """
    if not value:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


# « Nombres magiques » : les premiers octets d'un fichier disent ce qu'il est VRAIMENT,
# quel que soit son nom. Un escroc peut appeler « facture.tar » une archive RAR.
_MAGIC = [
    (b"Rar!\x1a\x07", "rar"),
    (b"PK\x03\x04", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF", "pdf"),
    (b"MZ", "exe"),
    (b"\xd0\xcf\x11\xe0", "ole"),   # ancien format Office (.doc, .xls)
]


def _file_type(data: bytes) -> str:
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            return kind
    return ""


def _fix_raw_utf8(text: str) -> str:
    """Un en-tête écrit directement en UTF-8 (sans encodage =?...?=) arrive « cassé » par Python
    (caractères de remplacement invisibles). On le répare pour lire les vrais caractères."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def _raw_header(msg: Message, name: str) -> str:
    """Valeur BRUTE d'un en-tête, avec les caractères UTF-8 non encodés réparés."""
    for key, value in msg.raw_items():
        if key.lower() == name.lower():
            return _fix_raw_utf8(str(value))
    return ""


def _filename(part: Message) -> str:
    """Nom de la pièce jointe, décodé. Si Python l'a abîmé (UTF-8 brut), on le relit depuis
    l'en-tête brut : sinon un caractère piégé comme U+202E deviendrait invisible pour nous."""
    name = _decode_header(part.get_filename() or "")
    if "\ufffd" in name:
        clean = Message()
        clean["Content-Disposition"] = _raw_header(part, "Content-Disposition")
        name = clean.get_filename() or name
    return name


def _split_address(raw) -> tuple[str, str]:
    """'=?UTF-8?Q?Banque_Lumi=C3=A8re?= <a@b.fr>' -> ('Banque Lumière', 'a@b.fr').

    SÉCURITÉ : on extrait l'adresse depuis l'en-tête BRUT, PUIS on décode le nom seul.
    Dans cet ordre, un nom encodé qui cache une fausse adresse ne trompe pas parseaddr.
    """
    name, address = parseaddr(str(raw or ""))
    return _decode_header(name), address.lower()


def _all_addresses(raw) -> list[str]:
    """Toutes les adresses d'un en-tête (To: peut en contenir plusieurs)."""
    return [a.lower() for _n, a in getaddresses([str(raw or "")]) if "@" in a]


def parse_eml(raw_bytes: bytes) -> ParsedMail:
    msg: Message = email.message_from_bytes(raw_bytes)

    plain, html = "", ""
    attachments = []
    attachment_info = []
    for part in msg.walk():   # walk() parcourt toutes les parties (marche aussi pour un mail simple)
        if part.is_multipart():
            continue          # c'est juste une « enveloppe » qui contient d'autres parties
        filename = part.get_filename()
        disp = str(part.get("Content-Disposition") or "")
        if filename or "attachment" in disp:
            name = _filename(part) or "(sans nom)"
            attachments.append(name)
            data = part.get_payload(decode=True) or b""
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            # Le texte d'une pièce jointe HTML est gardé EN MÉMOIRE pour l'analyse, jamais en base.
            text = data.decode("utf-8", errors="ignore") if ext in ("html", "htm", "shtml", "svg") else ""
            attachment_info.append({"name": name, "content_type": part.get_content_type(),
                                    "file_type": _file_type(data[:8]), "text": text})
        elif part.get_content_type() == "text/plain":
            plain += _decode(part)
        elif part.get_content_type() == "text/html":
            html += _decode(part)

    reader = _HTMLReader()
    if html:
        reader.feed(html)
    body = plain + "\n" + " ".join(reader.text)

    hrefs = [href for href, _ in reader.anchors if href.lower().startswith(("http://", "https://"))]
    links = list(dict.fromkeys(_LINK_RE.findall(plain) + hrefs))   # dict.fromkeys = enlève les doublons

    sender_name, sender_email = _split_address(_raw_header(msg, "From"))
    all_hrefs = [href.strip() for href, _ in reader.anchors if href]

    return ParsedMail(
        subject=_decode_header(_raw_header(msg, "Subject")),
        from_addr=_raw_header(msg, "From"),     # brut : voir _decode_header
        headers={
            # _raw_header renvoie toujours du texte. msg.get() peut renvoyer un objet « Header »
            # quand l'en-tête contient des accents non encodés : .lower() plantait alors.
            "authentication_results": _raw_header(msg, "Authentication-Results"),
            "reply_to": _raw_header(msg, "Reply-To"),   # brut : voir _decode_header
        },
        links=links,
        anchors=reader.anchors,
        attachments=attachments,
        body_text=body,
        sender_name=sender_name,
        sender_email=sender_email,
        reply_to_emails=_all_addresses(msg.get("Reply-To")),
        to_emails=_all_addresses(msg.get("To")),
        in_reply_to=str(msg.get("In-Reply-To") or ""),
        mailer=str(msg.get("X-Mailer") or ""),
        html_raw=html,
        plain_raw=plain,
        link_urls=list(dict.fromkeys(all_hrefs + _LINK_RE.findall(plain))),
        attachment_info=attachment_info,
    )
