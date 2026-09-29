"""Lit un fichier .eml et en extrait les informations utiles.

RGPD : on ne stocke JAMAIS le corps du mail ni les pièces jointes elles-mêmes,
seulement ce qui sert à l'analyse (métadonnées, liens, noms de fichiers).
"""
from __future__ import annotations

import email
import re
from email.message import Message
from dataclasses import dataclass, field

_LINK_RE = re.compile(r'https?://[^\s"\'<>]+')


@dataclass
class ParsedMail:
    subject: str = ""
    from_addr: str = ""
    headers: dict = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)   # noms de fichiers seulement
    body_text: str = ""   # utilisé UNIQUEMENT pendant l'analyse, jamais enregistré en base


def parse_eml(raw_bytes: bytes) -> ParsedMail:
    msg: Message = email.message_from_bytes(raw_bytes)

    body = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            elif part.get_content_type() == "text/plain" and "attachment" not in disp:
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
        except Exception:
            body = str(msg.get_payload())

    return ParsedMail(
        subject=msg.get("Subject", ""),
        from_addr=msg.get("From", ""),
        headers={
            "spf": msg.get("Received-SPF", ""),
            "dkim": msg.get("DKIM-Signature", ""),
            "authentication_results": msg.get("Authentication-Results", ""),
            "reply_to": msg.get("Reply-To", ""),
        },
        links=list(dict.fromkeys(_LINK_RE.findall(body))),
        attachments=attachments,
        body_text=body,
    )
