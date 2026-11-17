"""SQLite storage: demo sandboxes, tokens, the audit log and the approval queue.

Each visitor gets an isolated sandbox (a "session") with its own copy of the
policy, tokens and calendar, so one person's demo never changes another's.
The audit log is append-only: the app never updates or deletes audit rows,
except when a whole sandbox expires.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

DB_PATH = os.environ.get("AAM_DB_PATH", str(Path(__file__).resolve().parent.parent / "aam.db"))
SESSION_TTL_SECONDS = 24 * 3600
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    created_at    REAL NOT NULL,
    policy_json   TEXT NOT NULL,
    calendar_json TEXT NOT NULL,
    next_request  INTEGER NOT NULL DEFAULT 1001
);
CREATE TABLE IF NOT EXISTS tokens (
    jti        TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    token      TEXT NOT NULL,
    issued_at  REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    current    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS tokens_by_agent ON tokens (session_id, agent_id, current);
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    ts           REAL NOT NULL,
    requester    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    request_text TEXT NOT NULL,
    result       TEXT NOT NULL,
    reason       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_session ON audit_log (session_id, id);
CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    requester    TEXT NOT NULL,
    request_text TEXT NOT NULL,
    request_json TEXT NOT NULL,
    route_json   TEXT NOT NULL,
    approver     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_at   REAL,
    PRIMARY KEY (session_id, id)
);
CREATE TABLE IF NOT EXISTS pending_verifications (
    session_id   TEXT PRIMARY KEY,
    request_text TEXT NOT NULL,
    request_json TEXT NOT NULL,
    route_json   TEXT NOT NULL,
    expires_at   REAL NOT NULL
);
"""


def init() -> None:
    with connect() as db:
        db.executescript(SCHEMA)


@contextmanager
def connect():
    """One connection per unit of work, serialized so writes never collide."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def delete_expired_sessions(db: sqlite3.Connection, now: float) -> None:
    cutoff = now - SESSION_TTL_SECONDS
    old = [r["id"] for r in db.execute("SELECT id FROM sessions WHERE created_at < ?", (cutoff,))]
    for sid in old:
        for table in ("tokens", "audit_log", "approvals", "pending_verifications"):
            db.execute(f"DELETE FROM {table} WHERE session_id = ?", (sid,))
        db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
