"""Routes a plain-language request to an agent with simple keyword matching.

There is no AI here yet: each agent lists routing keywords in the policy, the
agent with the most matches wins, and a small parser works out the action and
its details. (A later version can swap this for a model that picks tools.)
"""

from __future__ import annotations

import re

from .checker import classify_software
from .text import fmt_time, has_word, normalize, parse_times


def route_request(text: str, policy: dict) -> dict | None:
    t = normalize(text)
    best = None
    for agent_id, agent in policy["agents"].items():
        hits = [k for k in agent["routingKeywords"] if has_word(t, k)]
        if hits and (best is None or len(hits) > len(best["hits"])):
            best = {"agent_id": agent_id, "hits": hits}
    if not best:
        return None
    parser = _PARSERS.get(best["agent_id"])
    if not parser:
        return None
    return {**best, **parser(t, text, policy)}


def _calendar(t: str, _original: str, _policy: dict) -> dict:
    day = "tomorrow" if re.search(r"\btomorrow\b", t) else "today"
    times = parse_times(t)
    if re.search(r"\b(cancel|delete|remove|clear|drop|wipe)\b", t):
        everything = bool(re.search(r"\b(all|every|everything)\b", t)) or not times
        return {"action": "delete_calendar",
                "params": {"day": day, "all": everything, "at": None if everything else times[0]},
                "summary": f"Cancel all meetings {day}" if everything else f"Cancel the {fmt_time(times[0])} meeting {day}"}
    if re.search(r"\b(move|reschedule|push|shift|change|bump|postpone)\b", t):
        start = times[0] if times else None
        to = times[1] if len(times) > 1 else None
        return {"action": "update_calendar", "params": {"day": day, "from": start, "to": to},
                "summary": f"Meeting at {fmt_time(start)} {day} → {fmt_time(to)}"}
    return {"action": "read_calendar", "params": {"day": day}, "summary": f"Show meetings {day}"}


def _password(t: str, _original: str, policy: dict) -> dict:
    other_word = re.search(r"\b(manager|boss|supervisor|colleague|co-?worker|teammate|someone|somebody|another user|ceo|cfo|cto)\b", t)
    possessive = re.search(r"\b(?!my\b)([a-z]+)'s\s+password", t)
    for_other = re.search(r"\bfor\s+(?!me\b|myself\b|my\b)([a-z]+)", t)
    user = policy["demoUser"]
    subject, label = "self", f"Requesting user ({user['name']})"
    if other_word or possessive or for_other:
        subject = "other"
        who = (other_word or possessive or for_other).group(1)
        label = f"Your manager ({user['manager']})" if who == "manager" else f"Another user ({who})"
    return {"action": "reset_password", "subject": subject, "subject_label": label,
            "summary": f"Reset password for: {label}"}


def _software(t: str, original: str, policy: dict) -> dict:
    found = classify_software(t, policy)
    name = found["name"] if found["category"] != "unlisted" else None
    if not name:
        m = re.search(r"(?:install|download|set up|setup)\s+(?:me\s+)?(?:a\s+|an\s+|the\s+)?(.+?)"
                      r"(?:\s+(?:on|for)\s+(?:my|me)\b.*)?[.!?]*$", original.strip(), re.IGNORECASE)
        name = m.group(1).strip() if m else "unknown software"
    return {"action": "install_software", "resource": {"type": "software", "name": name},
            "summary": f"Software: {name}"}


def _files(t: str, original: str, policy: dict) -> dict:
    rank = {"deny": 3, "approval": 2, "allow": 1}
    matches = [(fid, f) for fid, f in policy["folders"].items() if any(has_word(t, k) for k in f["keywords"])]
    matches.sort(key=lambda m: rank[m[1]["rule"]], reverse=True)  # most restrictive wins
    if not matches:
        m = re.search(r"(?:access to|open)\s+(?:the\s+|my\s+)?(.+?)[.!?]*$", original, re.IGNORECASE)
        label = m.group(1) if m else "unknown folder"
        return {"action": "request_folder_access", "resource": {"type": "folder", "id": None, "label": label},
                "summary": f"Folder: {label} (not in policy)"}
    fid, f = matches[0]
    return {"action": "read_own_files" if f.get("ownedByRequester") else "request_folder_access",
            "resource": {"type": "folder", "id": fid, "label": f["label"]},
            "summary": f"Folder: {f['label']} ({f['classification']})"}


_PARSERS = {"AGT-001": _calendar, "AGT-002": _password, "AGT-003": _software, "AGT-004": _files}
