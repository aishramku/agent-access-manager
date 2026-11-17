"""Request flows: route → verify the agent's token → check the policy → act → log.

Everything that decides or changes state lives here, on the server. The browser
only sends text and admin clicks, and renders what comes back.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from pathlib import Path

from . import db as dbm
from . import tokens
from .actions import execute, seed_calendar
from .checker import check_access
from .router import route_request
from .text import sentence

DEFAULT_POLICY: dict = json.loads((Path(__file__).parent / "policy.json").read_text(encoding="utf-8"))


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


# --------------------------------------------------------------------------- sessions

def create_session(db: sqlite3.Connection, now: float) -> str:
    dbm.delete_expired_sessions(db, now)
    sid = secrets.token_urlsafe(18)
    db.execute("INSERT INTO sessions (id, created_at, policy_json, calendar_json) VALUES (?, ?, ?, ?)",
               (sid, now, json.dumps(DEFAULT_POLICY), json.dumps(seed_calendar())))
    for agent_id in DEFAULT_POLICY["agents"]:
        tokens.issue(db, sid, agent_id, DEFAULT_POLICY, now=now)
    return sid


def load_session(db: sqlite3.Connection, sid: str) -> dict:
    row = db.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    if not row:
        raise NotFound("Unknown or expired session")
    return {"id": row["id"], "policy": json.loads(row["policy_json"]),
            "calendar": json.loads(row["calendar_json"]), "next_request": row["next_request"]}


def _save(db: sqlite3.Connection, sess: dict) -> None:
    db.execute("UPDATE sessions SET policy_json = ?, calendar_json = ?, next_request = ? WHERE id = ?",
               (json.dumps(sess["policy"]), json.dumps(sess["calendar"]), sess["next_request"], sess["id"]))


def _audit(db, sess, *, agent_id, action, text, result, reason, now, requester=None) -> None:
    db.execute(
        "INSERT INTO audit_log (session_id, ts, requester, agent_id, action, request_text, result, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sess["id"], now, requester or sess["policy"]["demoUser"]["name"], agent_id, action, text, result, reason),
    )


# --------------------------------------------------------------------------- state for the UI

def get_state(db: sqlite3.Connection, sess: dict, now: float, changed: list[str] | None = None) -> dict:
    policy = sess["policy"]
    token_state = {}
    for agent_id in policy["agents"]:
        row = tokens.current_token(db, sess["id"], agent_id)
        if row:
            token_state[agent_id] = {"preview": tokens.preview(row["token"]), "status": tokens.status_of(row, now),
                                     "issued_at": row["issued_at"], "expires_at": row["expires_at"]}
    approvals = [{
        "id": r["id"], "created_at": r["created_at"], "requester": r["requester"], "request_text": r["request_text"],
        "agent_id": json.loads(r["request_json"])["agent_id"], "action": json.loads(r["request_json"])["action"],
        "summary": json.loads(r["route_json"])["summary"], "approver": r["approver"], "reason": r["reason"],
    } for r in db.execute("SELECT * FROM approvals WHERE session_id = ? AND status = 'pending' ORDER BY created_at",
                          (sess["id"],))]
    audit = [dict(r) for r in db.execute(
        "SELECT id, ts, requester, agent_id, action, request_text, result, reason FROM audit_log "
        "WHERE session_id = ? ORDER BY id DESC LIMIT 200", (sess["id"],))]
    return {
        "policy_version": policy["policyVersion"],
        "agents": {aid: {"name": a["name"], "owner": a["owner"], "permissions": a["permissions"]}
                   for aid, a in policy["agents"].items()},
        "tokens": token_state,
        "approvals": approvals,
        "audit": audit,
        "calendar": sess["calendar"],
        "calendar_changed": changed or [],
        "pending_verification": _pending(db, sess, now) is not None,
    }


# --------------------------------------------------------------------------- request flows

def handle_request(db: sqlite3.Connection, sess: dict, text: str, now: float) -> dict:
    text = text.strip()
    policy = sess["policy"]
    notes: list[str] = []

    pending = _pending(db, sess, now)
    if pending:
        if re.fullmatch(r"\d{4,8}", text):
            return handle_verification(db, sess, text, now)
        db.execute("DELETE FROM pending_verifications WHERE session_id = ?", (sess["id"],))
        req = json.loads(pending["request_json"])
        _audit(db, sess, agent_id=req["agent_id"], action=req["action"], text=pending["request_text"],
               result="BLOCKED", reason="Verification cancelled by user", now=now)
        notes.append(f'Verification for "{pending["request_text"]}" was cancelled.')

    route = route_request(text, policy)
    if route is None:
        outcome = {"decision": "BLOCKED", "reason": "No agent is authorized to handle this request",
                   "checks": {"identity": [], "permission": []}}
        _audit(db, sess, agent_id="—", action="unrouted", text=text, result="BLOCKED", reason=outcome["reason"], now=now)
        return _result(text=text, agent_id=None, outcome=outcome, route=None, mode="request", notes=notes,
                       message="No agent is authorized to handle this request.")

    req = {"agent_id": route["agent_id"], "action": route["action"], "requester": policy["demoUser"]["name"],
           "subject": route.get("subject", "self"), "subject_label": route.get("subject_label"),
           "resource": route.get("resource"), "params": route.get("params", {})}
    return _decide_and_finish(db, sess, text=text, route=route, req=req, mode="request", now=now, notes=notes)


def handle_verification(db: sqlite3.Connection, sess: dict, code: str, now: float) -> dict:
    pending = _pending(db, sess, now)
    if not pending:
        raise Conflict("No verification is in progress")
    db.execute("DELETE FROM pending_verifications WHERE session_id = ?", (sess["id"],))
    req = json.loads(pending["request_json"])
    req["verification_code"] = code.strip()  # used for this check only, never stored
    return _decide_and_finish(db, sess, text=pending["request_text"], route=json.loads(pending["route_json"]),
                              req=req, mode="verification", now=now)


def decide_approval(db: sqlite3.Connection, sess: dict, approval_id: str, approve: bool, now: float) -> dict:
    row = db.execute("SELECT * FROM approvals WHERE session_id = ? AND id = ?", (sess["id"], approval_id)).fetchone()
    if not row:
        raise NotFound(f"No approval request {approval_id}")
    if row["status"] != "pending":
        raise Conflict(f"{approval_id} was already {row['status']}")
    db.execute("UPDATE approvals SET status = ?, decided_at = ? WHERE session_id = ? AND id = ?",
               ("approved" if approve else "denied", now, sess["id"], approval_id))
    req, route, text = json.loads(row["request_json"]), json.loads(row["route_json"]), row["request_text"]

    if not approve:
        reason = f"Denied by approver in admin console ({approval_id})"
        _audit(db, sess, agent_id=req["agent_id"], action=req["action"], text=text, result="BLOCKED", reason=reason, now=now)
        outcome = {"decision": "BLOCKED", "reason": "Denied by approver", "checks": {"identity": [], "permission": [
            {"status": "fail", "name": "Human approval", "detail": f"{row['approver']} denied {approval_id}"}]}}
        return _result(text=text, agent_id=req["agent_id"], outcome=outcome, route=route, mode="approval",
                       approval_id=approval_id, message=None, notes=[f'{approval_id} was denied: "{text}"'])

    # Re-run every check at execution time: an approved request is still blocked
    # if the agent's token was revoked or expired while it waited.
    req["approved_by"] = f"{row['approver']} via admin console"
    return _decide_and_finish(db, sess, text=text, route=route, req=req, mode="approval", now=now,
                              approval_id=approval_id, notes=[f'{approval_id} was approved. Running: "{text}"'])


def _decide_and_finish(db, sess, *, text, route, req, mode, now, notes=None, approval_id=None) -> dict:
    policy = sess["policy"]
    token = tokens.verify_agent(db, sess["id"], req["agent_id"], policy, now)
    outcome = check_access(req, {"policy": policy, "token": token, "now": now})
    decision, agent_id = outcome["decision"], req["agent_id"]
    common = {"text": text, "agent_id": agent_id, "outcome": outcome, "route": route, "mode": mode,
              "notes": notes or [], "approval_id": approval_id}

    if decision == "ALLOWED":
        done = execute(req, sess["calendar"], policy)
        _save(db, sess)
        reason = outcome["reason"] + (f". {done['note']}" if done["note"] else "")
        _audit(db, sess, agent_id=agent_id, action=req["action"], text=text, result="ALLOWED", reason=reason, now=now)
        return _result(**common, message=done["message"], items=done["items"], exec_note=done["note"],
                       changed=done["changed"])

    if decision == "BLOCKED":
        _audit(db, sess, agent_id=agent_id, action=req["action"], text=text, result="BLOCKED",
               reason=outcome["reason"], now=now)
        return _result(**common, message=f"I can't do that. {sentence(outcome['reason'])}")

    if decision == "NEEDS_APPROVAL":
        new_id = f"REQ-{sess['next_request']}"
        sess["next_request"] += 1
        _save(db, sess)
        db.execute("INSERT INTO approvals (id, session_id, created_at, requester, request_text, request_json, route_json, "
                   "approver, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (new_id, sess["id"], now, req["requester"], text, json.dumps(req), json.dumps(route),
                    outcome["approver"], outcome["reason"]))
        _audit(db, sess, agent_id=agent_id, action=req["action"], text=text, result="NEEDS_APPROVAL",
               reason=f"{outcome['reason']}. Queued as {new_id}", now=now)
        common["approval_id"] = new_id
        return _result(**common, message=f"This needs approval from {outcome['approver']}. I've added it to the "
                                         f"approval queue as {new_id} and I'll run it once it's approved.")

    # NEEDS_VERIFICATION: remember the request until the user sends the code.
    ver = policy["verification"]
    db.execute("INSERT OR REPLACE INTO pending_verifications (session_id, request_text, request_json, route_json, expires_at) "
               "VALUES (?, ?, ?, ?, ?)", (sess["id"], text, json.dumps(req), json.dumps(route), now + ver["ttlSeconds"]))
    return _result(**common, message=f"To confirm it's you, enter the 6-digit code sent via {ver['channel']}.",
                   hint=f"Demo code: {ver['demoCode']}")


def _pending(db, sess, now):
    row = db.execute("SELECT * FROM pending_verifications WHERE session_id = ?", (sess["id"],)).fetchone()
    if row and row["expires_at"] <= now:
        db.execute("DELETE FROM pending_verifications WHERE session_id = ?", (sess["id"],))
        return None
    return row


def _result(*, text, agent_id, outcome, route, mode, message, notes=None, items=None, hint=None,
            exec_note=None, approval_id=None, changed=None) -> dict:
    return {
        "request_text": text,
        "agent_id": agent_id,
        "decision": outcome["decision"],
        "reason": outcome["reason"],
        "outcome": outcome,
        "route": None if route is None else {k: route.get(k) for k in ("agent_id", "action", "hits", "summary")},
        "mode": mode,
        "message": message,
        "items": items or [],
        "hint": hint,
        "exec_note": exec_note,
        "approval_id": approval_id,
        "notes": notes or [],
        "changed": changed or [],
    }


# --------------------------------------------------------------------------- admin actions

def set_permission(db, sess, agent_id: str, permission: str, enabled: bool, now: float) -> str:
    agent = sess["policy"]["agents"].get(agent_id)
    if not agent:
        raise NotFound(f"Unknown agent {agent_id}")
    if permission not in agent["permissions"]:
        # Admins can switch existing permissions on or off, but can't invent new ones here.
        raise NotFound(f"{agent_id} has no permission named {permission}")
    agent["permissions"][permission] = enabled
    _save(db, sess)
    _audit(db, sess, agent_id=agent_id, action="policy_change", text="Admin console", result="ADMIN",
           reason=f'Permission "{permission}" turned {"ON" if enabled else "OFF"}', now=now, requester="IT Admin")
    return f"{agent_id}: {permission} turned {'on' if enabled else 'off'}"


def revoke_token(db, sess, agent_id: str, now: float) -> str:
    _require_agent(sess, agent_id)
    shown = tokens.revoke(db, sess["id"], agent_id)
    if not shown:
        raise NotFound(f"{agent_id} has no token")
    _audit(db, sess, agent_id=agent_id, action="token_revoke", text="Admin console", result="ADMIN",
           reason=f"Token {shown} revoked", now=now, requester="IT Admin")
    return f"{agent_id} token revoked. All its requests are now blocked."


def rotate_token(db, sess, agent_id: str, now: float) -> str:
    _require_agent(sess, agent_id)
    old = tokens.revoke(db, sess["id"], agent_id)  # the old token can never be used again
    new = tokens.issue(db, sess["id"], agent_id, sess["policy"], now=now)
    _audit(db, sess, agent_id=agent_id, action="token_rotate", text="Admin console", result="ADMIN",
           reason=f"Token {old} replaced by {tokens.preview(new)}, expires in 60:00", now=now, requester="IT Admin")
    return f"{agent_id} issued a fresh token"


def expire_token(db, sess, agent_id: str, now: float) -> str:
    """Demo shortcut: end the token's lifetime now instead of waiting an hour."""
    _require_agent(sess, agent_id)
    row = tokens.current_token(db, sess["id"], agent_id)
    if not row:
        raise NotFound(f"{agent_id} has no token")
    tokens.force_expire(db, row["jti"], now)
    _audit(db, sess, agent_id=agent_id, action="token_expired", text="System", result="SYSTEM",
           reason=f"Token {tokens.preview(row['token'])} reached the end of its lifetime (simulated)", now=now,
           requester="IT Admin")
    return f"{agent_id} token expired"


def _require_agent(sess, agent_id):
    if agent_id not in sess["policy"]["agents"]:
        raise NotFound(f"Unknown agent {agent_id}")
