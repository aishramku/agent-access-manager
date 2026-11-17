"""The permission checker.

A pure function: a request and a context go in, a decision comes out. It reads
every rule from the policy and never touches the database or the network, so it
is easy to test and to reason about.

    request: {agent_id, action, requester, subject, subject_label, resource,
              verification_code?, approved_by?}
    context: {policy, token, now}
        token: the result of verifying the agent's JWT (see tokens.verify_agent):
               {status: valid|revoked|expired|invalid|missing, preview, expires_at, detail}

Returns {decision, reason, checks: {identity: [...], permission: [...]}, approver?}
where decision is ALLOWED, BLOCKED, NEEDS_APPROVAL or NEEDS_VERIFICATION.
"""

from __future__ import annotations

import hmac

from .text import fmt_duration, has_word


def check_access(request: dict, context: dict) -> dict:
    policy = context["policy"]
    token = context.get("token") or {"status": "missing", "preview": "(no token)"}
    now = context["now"]
    identity: list[dict] = []
    permission: list[dict] = []

    def check(lst: list, status: str, name: str, detail: str) -> None:
        lst.append({"status": status, "name": name, "detail": detail})

    def done(decision: str, reason: str, **extra) -> dict:
        return {"decision": decision, "reason": reason,
                "checks": {"identity": identity, "permission": permission}, **extra}

    # ---- Step 2: identity + token ----
    agent_id = request.get("agent_id")
    agent = policy["agents"].get(agent_id)
    if not agent:
        check(identity, "fail", "Agent identity", f'Unknown agent "{agent_id}"')
        return done("BLOCKED", "Unknown agent identity")
    check(identity, "pass", "Agent identity", f"{agent_id} · {agent['name']} (owner: {agent['owner']})")

    action = policy["actions"].get(request.get("action"))
    if not action or action["agent"] != agent_id:
        check(identity, "fail", "Agent ↔ action binding", f'{agent_id} is not registered for "{request.get("action")}"')
        return done("BLOCKED", "Agent is not registered for this action")

    status = token.get("status")
    preview = token.get("preview", "(no token)")
    if status == "missing":
        check(identity, "fail", "Access token", "The agent presented no token")
        return done("BLOCKED", "Missing token")
    if status == "invalid":
        check(identity, "fail", "Access token", f"{preview} failed verification: {token.get('detail', 'bad signature')}")
        return done("BLOCKED", "Invalid token")
    if status == "revoked":
        check(identity, "fail", "Access token", f"{preview} was revoked by an admin")
        return done("BLOCKED", "Token revoked")
    if status == "expired":
        check(identity, "fail", "Access token", f"{preview} has expired")
        return done("BLOCKED", "Token expired")
    check(identity, "pass", "Access token",
          f"{preview} valid · signature verified · expires in {fmt_duration(token['expires_at'] - now)}")

    # ---- Step 3: permission check against the policy ----
    perm = action["permission"]
    if not agent["permissions"].get(perm):
        check(permission, "fail", f"Permission: {perm}", "Not granted to this agent in the policy")
        return done("BLOCKED", f'{agent["name"]} does not have the "{perm}" permission')
    check(permission, "pass", f"Permission: {perm}", "Granted in policy")
    allow_reason = f'{agent["name"]} has the "{perm}" permission'

    if action.get("scope") == "self":
        if request.get("subject") != "self":
            check(permission, "fail", "Acting on behalf of",
                  f"{request.get('subject_label') or 'another user'}, not the requester")
            return done("BLOCKED", "Agents can only act for the requesting user")
        check(permission, "pass", "Acting on behalf of", f"Requesting user only ({request.get('requester')})")

    approval = None
    resource = request.get("resource") or {}

    if action.get("resourceType") == "software":
        sw = classify_software(resource.get("name"), policy)
        approver = policy["software"]["licensedApprover"]
        if sw["category"] == "approved":
            check(permission, "pass", "Software catalog", f"{sw['name']} is on the approved list")
            allow_reason = f"{sw['name']} is approved software"
        elif sw["category"] == "licensed":
            if request.get("approved_by"):
                check(permission, "pass", "Software catalog",
                      f"{sw['name']} is licensed · approved by {request['approved_by']}")
                allow_reason = f"{sw['name']} is licensed software, approved by {request['approved_by']}"
            else:
                check(permission, "warn", "Software catalog",
                      f"{sw['name']} is licensed software · needs sign-off from {approver}")
                approval = {"approver": approver,
                            "reason": f"{sw['name']} needs a paid license, so {approver} must approve it"}
        else:
            check(permission, "fail", "Software catalog",
                  f'"{sw["name"]}" is not on the approved or licensed list (default: deny)')
            return done("BLOCKED", f'"{sw["name"]}" is not approved software')

    if action.get("resourceType") == "folder":
        folder = policy["folders"].get(resource.get("id") or "")
        if not folder:
            check(permission, "fail", "Folder rule",
                  f'"{resource.get("label") or "Unknown folder"}" is not registered in the policy (default: deny)')
            return done("BLOCKED", "Folder is not registered in the policy")
        where = f"{folder['label']} · {folder['classification']}"
        if folder["rule"] == "deny":
            check(permission, "fail", "Folder rule", f"{where} · rule: deny")
            return done("BLOCKED", folder.get("denyReason") or "Folder access is denied by policy")
        if folder["rule"] == "approval":
            if request.get("approved_by"):
                check(permission, "pass", "Folder rule", f"{where} · approved by {request['approved_by']}")
                allow_reason = f"Access to {folder['label']} approved by {request['approved_by']}"
            else:
                check(permission, "warn", "Folder rule", f"{where} · rule: needs approval from {folder['approver']}")
                approval = {"approver": folder["approver"],
                            "reason": f"{folder['label']} is shared data, so {folder['approver']} must approve access"}
        else:
            check(permission, "pass", "Folder rule", f"{where} · rule: allow")
            allow_reason = f"{folder['label']} belongs to the requesting user"

    if approval:
        return done("NEEDS_APPROVAL", approval["reason"], approver=approval["approver"])

    if action.get("requiresVerification"):
        code = request.get("verification_code")
        channel = policy["verification"]["channel"]
        if not code:
            check(permission, "warn", "User verification", f"Code sent via {channel} · waiting for user")
            return done("NEEDS_VERIFICATION", "The user must verify their identity before the reset")
        # Constant-time comparison, as you would for any secret.
        if not hmac.compare_digest(str(code), str(policy["verification"]["demoCode"])):
            check(permission, "fail", "User verification", "Incorrect verification code")
            return done("BLOCKED", "Verification failed: incorrect code")
        check(permission, "pass", "User verification", "Code accepted")
        allow_reason = "User identity verified and the agent has the reset_own_password permission"

    return done("ALLOWED", allow_reason)


def classify_software(name: str | None, policy: dict) -> dict:
    raw = (name or "unknown software").strip()
    lc = raw.lower()
    sw = policy["software"]
    canonical = None
    for alias, real in sw["aliases"].items():
        if has_word(lc, alias):
            canonical = real
    for item in sw["approved"] + sw["licensed"]:
        if has_word(lc, item.lower()):
            canonical = item
    if canonical in sw["approved"]:
        return {"name": canonical, "category": "approved"}
    if canonical in sw["licensed"]:
        return {"name": canonical, "category": "licensed"}
    return {"name": raw, "category": "unlisted"}
