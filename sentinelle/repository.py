"""Accès à la base. Toutes les requêtes SQL passent ICI (et seulement ici).

Les "?" sont des requêtes paramétrées : les valeurs ne sont jamais collées
dans le texte SQL, ce qui empêche l'injection SQL.
"""
import json
from datetime import datetime, timezone

from .db import get_db


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_analysis(sha256: str, verdict: str, score: int, reasons: list[str]) -> None:
    get_db().execute("INSERT INTO analyses (sha256, verdict, score, reasons, created_at) VALUES (?,?,?,?,?)",
                     (sha256, verdict, score, json.dumps(reasons), now()))
    get_db().commit()


def list_analyses(limit: int = 20) -> list[dict]:
    rows = get_db().execute("SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "sha256": r["sha256"], "verdict": r["verdict"], "score": r["score"],
             "reasons": json.loads(r["reasons"]), "created_at": r["created_at"]} for r in rows]


def counts() -> dict:
    """Nombre total d'analyses, et combien par verdict."""
    db = get_db()
    result = {"total": db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]}
    for verdict in ("safe", "suspect", "dangerous"):
        result[verdict] = db.execute("SELECT COUNT(*) FROM analyses WHERE verdict=?", (verdict,)).fetchone()[0]
    return result
