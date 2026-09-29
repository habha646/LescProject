"""CONTRATS PARTAGÉS.

Ces structures sont la langue commune entre les modules (réseau, IA, mail, interface).
Ne PAS les modifier seul : en parler à l'équipe, noter la décision dans docs/DECISIONS.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITIES = ("info", "warning", "danger")
VERDICTS = ("safe", "suspect", "dangerous")


@dataclass
class Device:
    mac: str                      # identifiant unique, en minuscules "aa:bb:cc:dd:ee:ff"
    ip: str
    hostname: str = ""
    vendor: str = ""
    known: bool = False           # True = l'utilisateur a validé cet appareil
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    source: str                   # ex: "unknown_device", "mail"
    severity: str                 # "info" | "warning" | "danger"
    title: str                    # court, compréhensible par un non-technicien
    details: dict = field(default_factory=dict)   # données brutes (ip, mac, ...)
    dedupe_key: str = ""          # évite de recréer la même alerte en boucle
    explanation: Optional[str] = None   # rempli par le module IA
    id: Optional[int] = None
    created_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MailVerdict:
    verdict: str                  # "safe" | "suspect" | "dangerous"
    score: int                    # 0 (rien) à 100 (très dangereux)
    reasons: list[str] = field(default_factory=list)   # phrases lisibles en français
    links: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    explanation: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
