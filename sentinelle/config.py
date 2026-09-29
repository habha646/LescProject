import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _subnets(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


class Config:
    SECRET_KEY = os.environ.get("SENTINELLE_SECRET_KEY", "dev-only-change-me")
    DATABASE = os.environ.get("SENTINELLE_DB", str(BASE_DIR / "instance" / "sentinelle.db"))
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 Mo max pour un mail déposé
    NETWORK_MODE = os.environ.get("SENTINELLE_NETWORK_MODE", "fake")
    ALLOWED_SUBNETS = _subnets(os.environ.get("SENTINELLE_ALLOWED_SUBNETS", ""))
    AI_MODE = os.environ.get("SENTINELLE_AI_MODE", "template")
