import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SENTINELLE_SECRET_KEY", "dev-only-change-me")
    DATABASE = os.environ.get("SENTINELLE_DB", str(BASE_DIR / "instance" / "sentinelle.db"))
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 Mo max pour un mail déposé
    SAMPLES_DIR = BASE_DIR / "samples"    # jeu d'essai utilisé par l'auto-test au démarrage
