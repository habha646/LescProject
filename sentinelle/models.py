"""Structures de données partagées.

Pour l'instant une seule : le verdict d'analyse d'un mail.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

VERDICTS = ("safe", "suspect", "dangerous")


@dataclass
class MailVerdict:
    verdict: str                  # "safe" | "suspect" | "dangerous"
    score: int                    # 0 (rien) à 100 (très dangereux)
    reasons: list[str] = field(default_factory=list)   # phrases lisibles en français
    links: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    explanation: Optional[str] = None                   # conseil à afficher à l'utilisateur

    def to_dict(self) -> dict:
        return asdict(self)
