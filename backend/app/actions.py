"""Simulated company systems. These run only after an ALLOWED decision.

The calendar is real state stored per sandbox; the other systems return
realistic confirmations. In a production version these functions would call
Microsoft Graph, Entra ID, Intune and SharePoint.
"""

from __future__ import annotations

import time

from .checker import classify_software
from .text import fmt_time


def seed_calendar() -> dict:
    return {
        "today": [
            {"id": "m1", "title": "Team stand-up", "start": 9 * 60, "dur": 30},
            {"id": "m2", "title": "Design review", "start": 11 * 60, "dur": 60},
            {"id": "m3", "title": "Vendor sync: Fabrikam", "start": 14 * 60, "dur": 60},
        ],
        "tomorrow": [
            {"id": "m4", "title": "1:1 with Jordan", "start": 10 * 60, "dur": 30},
            {"id": "m5", "title": "Sprint planning", "start": 13 * 60, "dur": 60},
            {"id": "m6", "title": "Security awareness training", "start": 15 * 60 + 30, "dur": 60},
        ],
    }


def execute(req: dict, calendar: dict, policy: dict) -> dict:
    """Run an allowed action. Returns {message, items, note, changed} and may edit `calendar`."""
    action = req["action"]
    params = req.get("params") or {}
    user = policy["demoUser"]

    if action == "read_calendar":
        day = params.get("day", "today")
        meetings = sorted((m for m in calendar[day] if not m.get("cancelled") and not m.get("ghost")),
                          key=lambda m: m["start"])
        if not meetings:
            return _result(f"You have no meetings {day}.", note="No meetings found")
        return _result(f"Here's your calendar for {day}:",
                       items=[f"{fmt_time(m['start'])}: {m['title']}" for m in meetings],
                       note=f"Listed {len(meetings)} meeting(s)")

    if action == "update_calendar":
        day, start, to = params.get("day", "today"), params.get("from"), params.get("to")
        if start is None or to is None:
            return _result('I need both times. Try "Move my 2pm meeting to 4pm".', note="Missing time, no change made")
        meeting = next((m for m in calendar[day] if not m.get("cancelled") and not m.get("ghost")
                        and m["start"] == start), None)
        if not meeting:
            return _result(f"I checked your calendar and there's no meeting at {fmt_time(start)} {day}, so nothing changed.",
                           note=f"No meeting at {fmt_time(start)}, no change made")
        if to < 8 * 60 or to + meeting["dur"] > 18 * 60:
            return _result(f"{fmt_time(to)} is outside working hours (8 AM–6 PM), so I left the meeting where it is.",
                           note="Outside working hours, no change made")
        calendar[day] = [m for m in calendar[day] if m.get("ghostOf") != meeting["id"]]
        calendar[day].append({"id": f"{meeting['id']}-g{int(time.time() * 1000)}", "ghostOf": meeting["id"],
                              "title": meeting["title"], "start": meeting["start"], "dur": meeting["dur"], "ghost": True})
        meeting["start"] = to
        return _result(f'Done. "{meeting["title"]}" moved from {fmt_time(start)} to {fmt_time(to)} {day}. '
                       "Attendees were notified (simulated).",
                       note=f'Moved "{meeting["title"]}" {fmt_time(start)} → {fmt_time(to)}', changed=[meeting["id"]])

    if action == "delete_calendar":
        day = params.get("day", "today")
        targets = [m for m in calendar[day] if not m.get("cancelled") and not m.get("ghost")
                   and (params.get("all") or m["start"] == params.get("at"))]
        if not targets:
            return _result(f"There was nothing to cancel {day}.", note="Nothing to cancel")
        for m in targets:
            m["cancelled"] = True
        return _result(f"Cancelled {len(targets)} meeting(s) {day}: {', '.join(m['title'] for m in targets)}.",
                       note=f"Cancelled {len(targets)} meeting(s)", changed=[m["id"] for m in targets])

    if action == "reset_password":
        return _result("Your password has been reset. A temporary password was sent to your registered phone, "
                       "and you'll set a new one at next sign-in.", note="Password reset, temporary password sent")

    if action == "install_software":
        sw = classify_software((req.get("resource") or {}).get("name"), policy)
        return _result(f"{sw['name']} is installing on {user['device']} through the managed software portal "
                       "(simulated). It should be ready in about 3 minutes.",
                       note=f"Install of {sw['name']} started on {user['device']}")

    if action == "read_own_files":
        folder = policy["folders"][req["resource"]["id"]]
        return _result(f"Opened {folder['label']} ({folder['path']}):",
                       items=["Q4-roadmap.pptx", "migration-plan.docx", "budget-draft.xlsx"],
                       note=f"Opened {folder['label']}")

    if action == "request_folder_access":
        folder = policy["folders"][req["resource"]["id"]]
        return _result(f"Access granted to {folder['label']} (read & write) for 30 days.",
                       note=f"Access to {folder['label']} granted for 30 days")

    return _result("Done.")


def _result(message: str, items: list[str] | None = None, note: str = "", changed: list[str] | None = None) -> dict:
    return {"message": message, "items": items or [], "note": note, "changed": changed or []}
