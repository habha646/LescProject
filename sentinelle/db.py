"""Connexion à la base SQLite et création des tables."""
import sqlite3

from flask import current_app, g

SCHEMA = """
-- RGPD : on ne stocke JAMAIS le contenu d'un mail, seulement l'empreinte et le verdict.
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    reasons TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        get_db().executescript(SCHEMA)
