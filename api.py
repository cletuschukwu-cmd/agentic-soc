"""Backend API for the analyst investigation console.

Security-first, government-cloud enterprise design. Every request must carry a
valid identity (auth.py). Reject-by-default: no valid principal -> 401. The
user's role must permit the action -> else 403. Only then does the work run,
routed through the orchestrator to the right specialist, using the backend's
own identity to query — never the user's.

Two identities, cleanly separated:
  * USER identity (bearer token, validated by auth.py) governs WHO may ask and
    WHAT they may do.
  * BACKEND identity (managed identity / az login, inside the agents) does the
    actual querying.

The system prompt lives server-side; the analyst never sees or sets it.

Run locally:
    pip install "fastapi>=0.110,<1" "uvicorn[standard]>=0.29,<1"
    $env:AISOC_CUSTOMER  = "tier2lab"
    $env:AISOC_AUTH_MODE = "dev"
    $env:AISOC_DEV_KEY   = "dev-key"
    uvicorn api:app --port 8080
"""

import json
import logging

from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from pydantic import BaseModel

import auth
from customer import customer
from orchestrator import investigate as orchestrate, registry

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("aisoc.api")

app = FastAPI(title="AISOC Investigation Console")

# CORS: the console is same-origin in production. For local dev the page may be
# opened from a file, so localhost origins are permitted. Not "*", because these
# requests carry auth headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "null"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return authorization  # tolerate a raw token for dev convenience


def _principal(authorization: str | None) -> auth.Principal:
    """Resolve the caller or raise auth.AuthError."""
    return auth.authenticate(_bearer(authorization))


# --- error handling: auth failures become clean 401/403 --------------------

@app.exception_handler(auth.AuthError)
async def _auth_err(_req: Request, exc: auth.AuthError):
    return JSONResponse(status_code=401, content={"error": "unauthorized", "detail": str(exc)})


@app.exception_handler(auth.ForbiddenError)
async def _forbidden(_req: Request, exc: auth.ForbiddenError):
    return JSONResponse(status_code=403, content={"error": "forbidden", "detail": str(exc)})


# --- models -----------------------------------------------------------------

class Query(BaseModel):
    message: str


# --- endpoints --------------------------------------------------------------

@app.get("/api/health")
def health():
    """Unauthenticated liveness only. Reveals no data — just that the service is
    up and which customer/model it is bound to."""
    return {"status": "up", "customer": customer().name,
            "cloud": customer().cloud, "auth_mode": auth.AUTH_MODE}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    """Who am I, and what may I do. The frontend uses this to render the user
    and gate UI. Requires a valid identity."""
    p = _principal(authorization)
    return {"user": p.audit_dict(),
            "capabilities": [c.value for c in auth.Capability if p.can(c)]}


@app.get("/api/specialists")
def specialists(authorization: str | None = Header(default=None)):
    p = _principal(authorization)
    auth.require(p, auth.Capability.VIEW_RESULTS)
    return {"specialists": [a.card() for a in registry().values()]}


@app.post("/api/investigate")
def investigate(q: Query, authorization: str | None = Header(default=None)):
    """Run an investigation. Requires a valid identity AND the run capability.

    Streams the orchestrator's result. (Streaming of intermediate reasoning is
    added when the orchestrator exposes a streaming path; today the specialist
    runs and the result streams as a single terminal event, plus a start event
    so the UI can show progress.)
    """
    p = _principal(authorization)
    auth.require(p, auth.Capability.RUN_INVESTIGATION)

    log.info("investigation requested", extra={"user": p.subject})

    def event_stream():
        yield _sse({"type": "start", "user": p.display_name})
        try:
            result = orchestrate(q.message)
            # Attach the authenticated principal to the result for audit.
            result["requested_by"] = p.audit_dict()
            yield _sse({"type": "result", "data": result})
        except Exception as exc:  # noqa: BLE001
            log.exception("investigation failed")
            yield _sse({"type": "error", "reason": str(exc)[:300]})
        yield _sse({"type": "done"})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, default=str)}\n\n"


# --- serve the console (same origin as the API, so no CORS) -----------------

@app.get("/")
def console():
    """Serve the investigation console. Same origin as the API endpoints, which
    is also how it is served in production behind the container."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return FileResponse(os.path.join(here, "console.html"))
