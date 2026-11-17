# Agent Access Manager: backend

FastAPI service that enforces every access decision for the Agent Access Manager.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload       # http://127.0.0.1:8000  (API docs: /docs)
pip install -r requirements-dev.txt && pytest
```

**Design in one paragraph:** a request comes in as text. `router.py` matches it to an agent and an action. `tokens.py` takes that agent's current JWT from the credential store and verifies its signature, issuer, audience (the visitor's sandbox), subject (the agent), revocation status and expiry. `checker.py`, a pure function, then applies the rules in `policy.json`: the permission must be granted, self-only actions must target the requester, and software and folder rules allow, queue for approval, or deny. `service.py` runs the simulated system only on ALLOWED, stores approvals and pending verifications, and writes every outcome to the append-only audit log in SQLite.

See the main [README](../README.md) for the full picture, configuration and deployment.
