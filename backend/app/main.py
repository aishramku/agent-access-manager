"""Agent Access Manager API (v2).

Run locally:   uvicorn app.main:app --reload     (from the backend/ folder)
API docs:      http://127.0.0.1:8000/docs
The web app:   http://127.0.0.1:8000/            (served from ../index.html)
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import db as dbm
from . import service

VERSION = "2.0.0"
FRONTEND = Path(__file__).resolve().parents[2] / "index.html"
SESSION_HEADER = Header(..., alias="X-Session-Id", min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    dbm.init()
    yield


app = FastAPI(title="Agent Access Manager API", version=VERSION, lifespan=lifespan,
              description="Authorization layer for AI agents: identity, JWT tokens, least-privilege policy, "
                          "human approval and audit logging. All company systems are simulated.")

_origins = [o.strip() for o in os.environ.get("AAM_ALLOWED_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST", "PUT"],
                   allow_headers=["Content-Type", "X-Session-Id"])


@app.exception_handler(service.NotFound)
async def _not_found(_req: Request, exc: service.NotFound):
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(service.Conflict)
async def _conflict(_req: Request, exc: service.Conflict):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


# ------------------------------------------------------------------ models

class RequestIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500, examples=["Move my 2pm meeting to 4pm"])


class VerifyIn(BaseModel):
    code: str = Field(..., pattern=r"^\d{4,8}$", examples=["123456"])


class PermissionIn(BaseModel):
    enabled: bool


# ------------------------------------------------------------------ routes

@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.post("/api/sessions", status_code=201)
def create_session():
    """Create an isolated demo sandbox with its own policy, tokens and calendar."""
    now = time.time()
    with dbm.connect() as db:
        sid = service.create_session(db, now)
        return {"session_id": sid, "state": service.get_state(db, service.load_session(db, sid), now)}


@app.get("/api/state")
def get_state(session_id: str = SESSION_HEADER):
    now = time.time()
    with dbm.connect() as db:
        return service.get_state(db, service.load_session(db, session_id), now)


@app.post("/api/requests")
def submit_request(body: RequestIn, session_id: str = SESSION_HEADER):
    """Send a plain-language request. The server routes it, verifies the agent's token and checks the policy."""
    return _run(session_id, lambda db, sess, now: service.handle_request(db, sess, body.text, now))


@app.post("/api/verify")
def submit_code(body: VerifyIn, session_id: str = SESSION_HEADER):
    return _run(session_id, lambda db, sess, now: service.handle_verification(db, sess, body.code, now))


@app.post("/api/approvals/{approval_id}/approve")
def approve(approval_id: str, session_id: str = SESSION_HEADER):
    return _run(session_id, lambda db, sess, now: service.decide_approval(db, sess, approval_id, True, now))


@app.post("/api/approvals/{approval_id}/deny")
def deny(approval_id: str, session_id: str = SESSION_HEADER):
    return _run(session_id, lambda db, sess, now: service.decide_approval(db, sess, approval_id, False, now))


@app.put("/api/agents/{agent_id}/permissions/{permission}")
def set_permission(agent_id: str, permission: str, body: PermissionIn, session_id: str = SESSION_HEADER):
    return _admin(session_id, lambda db, sess, now: service.set_permission(db, sess, agent_id, permission, body.enabled, now))


@app.post("/api/agents/{agent_id}/token/revoke")
def revoke(agent_id: str, session_id: str = SESSION_HEADER):
    return _admin(session_id, lambda db, sess, now: service.revoke_token(db, sess, agent_id, now))


@app.post("/api/agents/{agent_id}/token/rotate")
def rotate(agent_id: str, session_id: str = SESSION_HEADER):
    return _admin(session_id, lambda db, sess, now: service.rotate_token(db, sess, agent_id, now))


@app.post("/api/agents/{agent_id}/token/expire")
def expire(agent_id: str, session_id: str = SESSION_HEADER):
    return _admin(session_id, lambda db, sess, now: service.expire_token(db, sess, agent_id, now))


@app.get("/", include_in_schema=False)
def web_app():
    if not FRONTEND.exists():
        raise HTTPException(404, "index.html not found next to the backend folder")
    return FileResponse(FRONTEND)


def _run(session_id, fn):
    now = time.time()
    with dbm.connect() as db:
        sess = service.load_session(db, session_id)
        result = fn(db, sess, now)
        return {"result": result, "state": service.get_state(db, sess, now, changed=result["changed"])}


def _admin(session_id, fn):
    now = time.time()
    with dbm.connect() as db:
        sess = service.load_session(db, session_id)
        notice = fn(db, sess, now)
        return {"notice": notice, "state": service.get_state(db, sess, now)}
