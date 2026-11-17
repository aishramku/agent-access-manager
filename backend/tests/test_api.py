"""End-to-end tests through the HTTP API, covering every scenario in the spec."""

import os
import tempfile

os.environ["AAM_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ.setdefault("AAM_JWT_SECRET", "test-secret-that-is-long-enough-for-hs256-signing")

import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbm  # noqa: E402
from app import tokens  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        sid = c.post("/api/sessions").json()["session_id"]
        c.headers["X-Session-Id"] = sid
        yield c


def ask(client, text):
    r = client.post("/api/requests", json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("text, decision, reason_part", [
    ("Move my 2pm meeting to 4pm", "ALLOWED", "update_calendar"),
    ("Cancel all my meetings tomorrow", "BLOCKED", "delete_calendar"),
    ("Reset my manager's password", "BLOCKED", "only act for the requesting user"),
    ("Install Zoom", "ALLOWED", "Zoom is approved"),
    ("Install Photoshop", "NEEDS_APPROVAL", "IT Asset Management"),
    ("Install a free VPN", "BLOCKED", "not approved software"),
    ("Open my project files", "ALLOWED", "belongs to the requesting user"),
    ("Give me access to the Marketing shared folder", "NEEDS_APPROVAL", "Jordan Lee"),
    ("Give me access to the HR salary folder", "BLOCKED", "sensitive data"),
    ("Order me a pizza", "BLOCKED", "No agent is authorized"),
])
def test_spec_scenarios(client, text, decision, reason_part):
    res = ask(client, text)["result"]
    assert res["decision"] == decision
    assert reason_part in res["reason"]


def test_calendar_move_updates_state(client):
    body = ask(client, "Move my 2pm meeting to 4pm")
    vendor = next(m for m in body["state"]["calendar"]["today"] if m["id"] == "m3")
    assert vendor["start"] == 16 * 60
    assert body["state"]["calendar_changed"] == ["m3"]


def test_password_reset_needs_correct_code(client):
    assert ask(client, "Reset my password")["result"]["decision"] == "NEEDS_VERIFICATION"
    bad = client.post("/api/verify", json={"code": "654321"}).json()["result"]
    assert bad["decision"] == "BLOCKED" and "incorrect code" in bad["reason"]

    assert ask(client, "Reset my password")["result"]["decision"] == "NEEDS_VERIFICATION"
    good = client.post("/api/verify", json={"code": "123456"}).json()
    assert good["result"]["decision"] == "ALLOWED"
    assert good["state"]["pending_verification"] is False


def test_code_is_never_written_to_the_audit_log(client):
    ask(client, "Reset my password")
    state = client.post("/api/verify", json={"code": "123456"}).json()["state"]
    assert all("123456" not in (e["request_text"] + e["reason"]) for e in state["audit"])


def test_permission_toggle_changes_next_decision(client):
    r = client.put("/api/agents/AGT-001/permissions/update_calendar", json={"enabled": False})
    assert r.status_code == 200
    assert ask(client, "Move my 2pm meeting to 4pm")["result"]["decision"] == "BLOCKED"


def test_cannot_invent_new_permissions(client):
    r = client.put("/api/agents/AGT-001/permissions/admin_everything", json={"enabled": True})
    assert r.status_code == 404


def test_revoke_and_rotate(client):
    client.post("/api/agents/AGT-003/token/revoke")
    assert ask(client, "Install Slack")["result"]["reason"] == "Token revoked"
    client.post("/api/agents/AGT-003/token/rotate")
    assert ask(client, "Install Slack")["result"]["decision"] == "ALLOWED"


def test_expired_token_blocks(client):
    client.post("/api/agents/AGT-004/token/expire")
    assert ask(client, "Open my project files")["result"]["reason"] == "Token expired"


def test_approve_runs_the_action(client):
    approval_id = ask(client, "Install Photoshop")["result"]["approval_id"]
    body = client.post(f"/api/approvals/{approval_id}/approve").json()
    assert body["result"]["decision"] == "ALLOWED"
    assert body["state"]["approvals"] == []
    assert client.post(f"/api/approvals/{approval_id}/approve").status_code == 409  # can't approve twice


def test_approval_still_blocked_if_token_revoked_meanwhile(client):
    approval_id = ask(client, "Give me access to the Marketing shared folder")["result"]["approval_id"]
    client.post("/api/agents/AGT-004/token/revoke")
    res = client.post(f"/api/approvals/{approval_id}/approve").json()["result"]
    assert res["decision"] == "BLOCKED" and res["reason"] == "Token revoked"


def test_deny_logs_blocked(client):
    approval_id = ask(client, "Install Photoshop")["result"]["approval_id"]
    state = client.post(f"/api/approvals/{approval_id}/deny").json()["state"]
    assert state["audit"][0]["result"] == "BLOCKED"
    assert "Denied by approver" in state["audit"][0]["reason"]


def test_sessions_are_isolated(client):
    client.put("/api/agents/AGT-001/permissions/update_calendar", json={"enabled": False})
    other = TestClient(app)
    other.headers["X-Session-Id"] = other.post("/api/sessions").json()["session_id"]
    assert ask(other, "Move my 2pm meeting to 4pm")["result"]["decision"] == "ALLOWED"


def test_unknown_session_is_rejected():
    with TestClient(app) as c:
        r = c.get("/api/state", headers={"X-Session-Id": "x" * 24})
        assert r.status_code == 404


def test_tokens_never_reach_the_browser(client):
    state = client.get("/api/state").json()
    for t in state["tokens"].values():
        assert "…" in t["preview"] and len(t["preview"]) < 20


# ---------------------------------------------------------------- token verification

def _session_and_policy(client):
    from app import service
    with dbm.connect() as db:
        sess = service.load_session(db, client.headers["X-Session-Id"])
    return sess["id"], sess["policy"]


def test_tampered_token_is_invalid(client):
    sid, policy = _session_and_policy(client)
    forged = jwt.encode({"iss": policy["tokenPolicy"]["issuer"], "aud": sid, "sub": "AGT-003", "jti": "x",
                         "iat": 0, "exp": 9999999999}, "wrong-secret", algorithm="HS256")
    with dbm.connect() as db:
        result = tokens.verify(db, forged, sid, "AGT-003", policy)
    assert result["status"] == "invalid"


def test_token_for_another_agent_is_invalid(client):
    sid, policy = _session_and_policy(client)
    with dbm.connect() as db:
        calendar_token = tokens.current_token(db, sid, "AGT-001")["token"]
        result = tokens.verify(db, calendar_token, sid, "AGT-003", policy)
    assert result["status"] == "invalid"
    assert "different agent" in result["detail"]
