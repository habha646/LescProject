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
from email.message import Message
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


def parse_eml(raw_bytes: bytes) -> ParsedMail:
    msg: Message = email.message_from_bytes(raw_bytes)

    plain, html = "", ""
    attachments = []
    for part in msg.walk():   # walk() parcourt toutes les parties (marche aussi pour un mail simple)
        if part.is_multipart():
            continue          # c'est juste une « enveloppe » qui contient d'autres parties
        filename = part.get_filename()
        disp = str(part.get("Content-Disposition") or "")
        if filename or "attachment" in disp:
            attachments.append(filename or "(sans nom)")
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

    return ParsedMail(
        subject=msg.get("Subject", ""),
        from_addr=msg.get("From", ""),
        headers={
            "authentication_results": msg.get("Authentication-Results", ""),
            "reply_to": msg.get("Reply-To", ""),
        },
        links=links,
        anchors=reader.anchors,
        attachments=attachments,
        body_text=body,
    )
