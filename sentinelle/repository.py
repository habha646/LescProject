"""Accès à la base. Toutes les requêtes SQL passent ICI (et seulement ici)."""
import json
from datetime import datetime, timezone

from .db import get_db
from .models import Alert, Device


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------- appareils ----------
def _device(row) -> Device:
    return Device(mac=row["mac"], ip=row["ip"], hostname=row["hostname"], vendor=row["vendor"],
                  known=bool(row["known"]), first_seen=row["first_seen"], last_seen=row["last_seen"])


def list_devices() -> list[Device]:
    rows = get_db().execute("SELECT * FROM devices ORDER BY known DESC, ip").fetchall()
    return [_device(r) for r in rows]


def upsert_devices(devices: list[Device], baseline: bool = False) -> list[Device]:
    """Enregistre les appareils vus. Retourne ceux qui sont NOUVEAUX.

    baseline=True : premier scan, tout est marqué "connu" (inventaire de départ).
    """
    db, ts, new = get_db(), now(), []
    for d in devices:
        mac = d.mac.lower()
        row = db.execute("SELECT mac FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row:
            db.execute("UPDATE devices SET ip=?, hostname=?, vendor=?, last_seen=? WHERE mac=?",
                       (d.ip, d.hostname, d.vendor, ts, mac))
        else:
            db.execute("INSERT INTO devices (mac, ip, hostname, vendor, known, first_seen, last_seen) "
                       "VALUES (?,?,?,?,?,?,?)", (mac, d.ip, d.hostname, d.vendor, int(baseline), ts, ts))
            new.append(_device(db.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()))
    db.commit()
    return new


def mark_known(mac: str) -> None:
    get_db().execute("UPDATE devices SET known=1 WHERE mac=?", (mac.lower(),))
    get_db().commit()


# ---------- alertes ----------
def _alert(row) -> Alert:
    return Alert(id=row["id"], dedupe_key=row["dedupe_key"], source=row["source"], severity=row["severity"],
                 title=row["title"], details=json.loads(row["details"]), explanation=row["explanation"],
                 created_at=row["created_at"])


def add_alert(a: Alert) -> bool:
    """Retourne False si une alerte avec le même dedupe_key existe déjà."""
    db = get_db()
    if a.dedupe_key and db.execute("SELECT 1 FROM alerts WHERE dedupe_key=?", (a.dedupe_key,)).fetchone():
        return False
    db.execute("INSERT INTO alerts (dedupe_key, source, severity, title, details, explanation, created_at) "
               "VALUES (?,?,?,?,?,?,?)",
               (a.dedupe_key or None, a.source, a.severity, a.title, json.dumps(a.details),
                a.explanation, now()))
    db.commit()
    return True


def list_alerts(limit: int = 100) -> list[Alert]:
    rows = get_db().execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_alert(r) for r in rows]


# ---------- analyses de mail ----------
def add_analysis(sha256: str, verdict: str, score: int, reasons: list[str]) -> None:
    get_db().execute("INSERT INTO analyses (sha256, verdict, score, reasons, created_at) VALUES (?,?,?,?,?)",
                     (sha256, verdict, score, json.dumps(reasons), now()))
    get_db().commit()


def list_analyses(limit: int = 20) -> list[dict]:
    rows = get_db().execute("SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "sha256": r["sha256"], "verdict": r["verdict"], "score": r["score"],
             "reasons": json.loads(r["reasons"]), "created_at": r["created_at"]} for r in rows]


def counts() -> dict:
    db = get_db()
    return {
        "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "unknown": db.execute("SELECT COUNT(*) FROM devices WHERE known=0").fetchone()[0],
        "alerts": db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "analyses": db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0],
    }
