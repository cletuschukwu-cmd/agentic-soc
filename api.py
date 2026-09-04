"""Backend API for the analyst investigation console.

One streaming endpoint. The analyst's natural-language message comes in; the
agent's reasoning and final verdict stream back as Server-Sent Events so the
frontend can show the investigation happening live rather than a blank wait.

The system prompt lives here, server-side. The analyst never sees or sets it.

Auth for the demo is a single shared key in the AISOC_API_KEY environment
variable (or the active customer profile's `extra.api_key`). Real per-analyst
Entra login is a later addition; this keeps the surface simple for now.

Run locally:
    pip install "fastapi>=0.110,<1" "uvicorn[standard]>=0.29,<1"
    $env:AISOC_CUSTOMER = "tier2lab"
    $env:AISOC_API_KEY  = "dev-key"
    uvicorn api:app --reload --port 8080
"""

import json
import os
import re

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import config
from agent import investigate_stream
from customer import customer
from envelope import build_envelope, run_kql

app = FastAPI(title="AISOC Investigation Console")

# The frontend is served from the same origin in production; for local dev the
# static file may be opened separately, so allow localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_INCIDENT_RE = re.compile(r"\bincident\s+#?(\d{1,7})\b", re.IGNORECASE)


def _api_key() -> str:
    return os.environ.get("AISOC_API_KEY") or customer().extra.get("api_key", "")


def _authorize(provided: str | None) -> None:
    expected = _api_key()
    if not expected:
        return  # no key configured -> open, for local dev only
    if provided != expected:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


class Query(BaseModel):
    message: str
    incident_number: int | None = None


@app.get("/api/health")
def health():
    checks = {"customer": customer().name, "cloud": customer().cloud,
              "model": customer().model_deployment}
    try:
        run_kql("SecurityIncident | take 1", days=1)
        checks["log_analytics"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["log_analytics"] = f"failed: {str(exc)[:120]}"
    return checks


@app.get("/api/customer")
def whoami():
    c = customer()
    return {"name": c.name, "cloud": c.cloud, "model": c.model_deployment}


@app.post("/api/investigate")
def investigate(q: Query, x_api_key: str | None = Header(default=None)):
    """Stream an investigation as Server-Sent Events."""
    _authorize(x_api_key)

    # If the analyst names an incident, seed the agent with its envelope.
    envelope = None
    incident_no = q.incident_number
    if incident_no is None:
        m = _INCIDENT_RE.search(q.message)
        if m:
            incident_no = int(m.group(1))
    if incident_no is not None:
        try:
            envelope = build_envelope(incident_no)
        except Exception:  # noqa: BLE001
            envelope = None  # fall back to open investigation

    def event_stream():
        yield _sse({"type": "start", "incident": incident_no})
        try:
            for event in investigate_stream(q.message, envelope=envelope):
                yield _sse(event)
        except Exception as exc:  # noqa: BLE001
            yield _sse({"type": "error", "reason": str(exc)[:300]})
        yield _sse({"type": "done"})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, default=str)}\n\n"
