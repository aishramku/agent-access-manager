"""Agent credentials: real signed JWTs, a credential store and a revocation list.

Each agent holds one current token, kept server-side in the `tokens` table (the
role Azure Key Vault plays in a real deployment). On every request the server
takes the agent's token and verifies it: signature, issuer, audience, subject,
revocation and expiry. Tokens never leave the server; the browser only sees a
masked preview.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
import warnings

import jwt

_SECRET = os.environ.get("AAM_JWT_SECRET")
if not _SECRET:
    _SECRET = secrets.token_urlsafe(48)
    warnings.warn("AAM_JWT_SECRET is not set; using a random secret, so tokens reset on restart.", stacklevel=1)

ALGORITHM = "HS256"


def preview(token: str) -> str:
    return f"{token[:8]}…{token[-4:]}"


def issue(db: sqlite3.Connection, session_id: str, agent_id: str, policy: dict,
          ttl_seconds: int | None = None, now: float | None = None) -> str:
    """Sign a new token for the agent and make it the agent's current token."""
    now = time.time() if now is None else now
    ttl = policy["tokenPolicy"]["ttlSeconds"] if ttl_seconds is None else ttl_seconds
    jti = secrets.token_hex(12)
    claims = {
        "iss": policy["tokenPolicy"]["issuer"],
        "aud": session_id,
        "sub": agent_id,
        "jti": jti,
        "iat": int(now),
        "exp": int(now + ttl),
        "scope": "agent",
    }
    token = jwt.encode(claims, _SECRET, algorithm=ALGORITHM)
    db.execute("UPDATE tokens SET current = 0 WHERE session_id = ? AND agent_id = ?", (session_id, agent_id))
    db.execute(
        "INSERT INTO tokens (jti, session_id, agent_id, token, issued_at, expires_at, revoked, current) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, 1)",
        (jti, session_id, agent_id, token, claims["iat"], claims["exp"]),
    )
    return token


def current_token(db: sqlite3.Connection, session_id: str, agent_id: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM tokens WHERE session_id = ? AND agent_id = ? AND current = 1",
        (session_id, agent_id),
    ).fetchone()


def revoke(db: sqlite3.Connection, session_id: str, agent_id: str) -> str | None:
    row = current_token(db, session_id, agent_id)
    if not row:
        return None
    db.execute("UPDATE tokens SET revoked = 1 WHERE jti = ?", (row["jti"],))
    return preview(row["token"])


def verify(db: sqlite3.Connection, token: str | None, session_id: str, agent_id: str,
           policy: dict, now: float | None = None) -> dict:
    """Verify a presented token and describe the result for the checker."""
    now = time.time() if now is None else now
    if not token:
        return {"status": "missing", "preview": "(no token)"}
    shown = preview(token)
    try:
        # Signature, issuer and audience are checked here; expiry is checked
        # below so we can tell "expired" apart from "revoked" in the trace.
        claims = jwt.decode(
            token, _SECRET, algorithms=[ALGORITHM],
            issuer=policy["tokenPolicy"]["issuer"], audience=session_id,
            options={"verify_exp": False, "require": ["exp", "iat", "jti", "sub", "iss", "aud"]},
        )
    except jwt.InvalidTokenError as exc:
        return {"status": "invalid", "preview": shown, "detail": str(exc)}
    if claims["sub"] != agent_id:
        return {"status": "invalid", "preview": shown, "detail": "token was issued to a different agent"}
    row = db.execute("SELECT revoked, expires_at FROM tokens WHERE jti = ?", (claims["jti"],)).fetchone()
    if row is None:
        return {"status": "invalid", "preview": shown, "detail": "unknown token id"}
    # The server may shorten a token's life (forced expiry), never extend it.
    expires_at = min(claims["exp"], row["expires_at"])
    if row["revoked"]:
        return {"status": "revoked", "preview": shown, "expires_at": expires_at}
    if now >= expires_at:
        return {"status": "expired", "preview": shown, "expires_at": expires_at}
    return {"status": "valid", "preview": shown, "expires_at": expires_at}


def force_expire(db: sqlite3.Connection, jti: str, now: float) -> None:
    db.execute("UPDATE tokens SET expires_at = MIN(expires_at, ?) WHERE jti = ?", (now, jti))


def verify_agent(db: sqlite3.Connection, session_id: str, agent_id: str, policy: dict,
                 now: float | None = None) -> dict:
    """The agent presents its current token from the credential store."""
    row = current_token(db, session_id, agent_id)
    return verify(db, row["token"] if row else None, session_id, agent_id, policy, now)


def status_of(row: sqlite3.Row, now: float | None = None) -> str:
    now = time.time() if now is None else now
    if row["revoked"]:
        return "revoked"
    return "expired" if now >= row["expires_at"] else "valid"
