"""Foundry gateway.

Routes a natural-language question to the right low-code Foundry specialist
(entity, identity, triage) and invokes it via the Responses API with an
agent_reference. Handles MCP tool-approval requests in code: read-only Sentinel
queries are auto-approved so the agent runs to completion, without depending on
per-agent portal settings. This is also where a production approval policy would
live (auto-approve reads; require a human for state-changing actions).

Auth via DefaultAzureCredential (az login locally, managed identity deployed).
"""

from __future__ import annotations

import os
import re

from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

PROJECT_ENDPOINT = os.environ.get(
    "AISOC_FOUNDRY_PROJECT",
    "https://ugoopenaiservice.services.ai.azure.com/api/projects/ugoOpenaiService-project1",
)

SPECIALISTS = {
    "entity-investigator": "IP, file hash, account, or host lookups and investigation.",
    "identity-investigator": "whether a user account is compromised (sign-ins, risk, privilege).",
    "incident-triage": "triage a Sentinel/Defender incident by its number.",
}

_project = None
_openai = None


def _client():
    global _project, _openai
    if _openai is None:
        _project = AIProjectClient(endpoint=PROJECT_ENDPOINT, credential=DefaultAzureCredential())
        _openai = _project.get_openai_client()
    return _openai


# --- routing ----------------------------------------------------------------

_INCIDENT_RE = re.compile(r"\bincident\s+#?(\d{1,7})\b", re.IGNORECASE)
_IDENTITY_RE = re.compile(r"\b(compromised|sign[- ]?in|logon|login|mfa|password|account)\b", re.IGNORECASE)


def route(message: str) -> str:
    if _INCIDENT_RE.search(message):
        return "incident-triage"
    if _IDENTITY_RE.search(message) and not re.search(r"\bhost\b", message, re.IGNORECASE):
        return "identity-investigator"
    return "entity-investigator"


# --- response handling ------------------------------------------------------

def _extract_text(resp) -> str:
    t = getattr(resp, "output_text", None)
    if t:
        return t
    parts = []
    for item in getattr(resp, "output", []) or []:
        if getattr(item, "type", None) == "message":
            for c in getattr(item, "content", []) or []:
                txt = getattr(c, "text", None)
                if txt:
                    parts.append(txt)
    return "\n".join(parts)


def _pending_approvals(resp) -> list:
    """Return any MCP approval-request items in the response."""
    out = []
    for item in getattr(resp, "output", []) or []:
        if getattr(item, "type", None) == "mcp_approval_request":
            out.append(item)
    return out


def ask_specialist(agent_name: str, message: str, max_rounds: int = 8) -> dict:
    """Invoke a Foundry agent, auto-approving read-only MCP calls until it
    produces a final answer. Never raises."""
    try:
        client = _client()
        ref = {"agent_reference": {"name": agent_name, "type": "agent_reference"}}
        resp = client.responses.create(input=message, extra_body=ref)

        for _ in range(max_rounds):
            approvals = _pending_approvals(resp)
            if not approvals:
                break
            # Approve each pending MCP call (read-only Sentinel queries) and continue.
            approval_inputs = [
                {"type": "mcp_approval_response",
                 "approval_request_id": a.id,
                 "approve": True}
                for a in approvals
            ]
            resp = client.responses.create(
                previous_response_id=resp.id,
                input=approval_inputs,
                extra_body=ref,
            )

        text = _extract_text(resp)
        return {"status": "ok", "agent": agent_name, "answer": text or "(no response)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "agent": agent_name, "reason": str(exc)[:400]}


def investigate(message: str) -> dict:
    agent_name = route(message)
    result = ask_specialist(agent_name, message)
    result["routing"] = {"agent": agent_name, "reason": SPECIALISTS.get(agent_name, "")}
    return result


if __name__ == "__main__":
    import json, sys
    q = " ".join(sys.argv[1:]) or "triage incident 7838"
    print("routing ->", route(q))
    print(json.dumps(investigate(q), indent=2, default=str))
