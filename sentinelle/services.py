"""Actions partagées entre la page « Analyse mail » et la console (API JSON)."""
from __future__ import annotations

import hashlib

from . import repository as repo
from .models import MailVerdict
from .modules.mail import analyze_eml


def analyze_and_store(raw: bytes) -> MailVerdict:
    """Analyse un mail brut et n'enregistre que son empreinte et le verdict."""
    verdict = analyze_eml(raw)
    # RGPD : on garde seulement l'empreinte (sha256), jamais le contenu du mail
    digest = hashlib.sha256(raw).hexdigest()
    repo.add_analysis(digest, verdict.verdict, verdict.score, verdict.reasons)
    return verdict
