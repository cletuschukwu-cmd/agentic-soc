"""Orchestrator — the supervisor of the multi-agent platform.

The analyst asks one question in natural language. The orchestrator decides
which specialist should handle it, dispatches to that specialist, and returns
its grounded result. It is the single entry point the frontend talks to, so
adding a new specialist never changes the frontend — it just registers here.

Two things the orchestrator owns that a loose collection of agents cannot:

  Routing. It reads the analyst's intent and picks the specialist whose
  description best fits, using the model itself as the router. Unknown or
  ambiguous requests get a clean "which did you mean" rather than a guess.

  Agent-to-agent calls. A specialist can ask the orchestrator to consult
  another specialist mid-investigation (entity investigation escalating a
  suspicious account to the identity specialist, once that exists). The calling
  agent never gains the callee's privileges — the callee runs under its own
  scope and returns only its result. That is how least-privilege survives
  composition.

Like every agent in this platform, the orchestrator is read-and-reason only.
It routes and composes; it never takes a state-changing action.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from openai import AzureOpenAI
from azure.identity import get_bearer_token_provider

import config
import config
from agent_base import Specialist
from entity_specialist import EntitySpecialist
from triage_specialist import TriageSpecialist
from identity_specialist import IdentitySpecialist
from threatintel_specialist import ThreatIntelSpecialist
from correlation_specialist import CorrelationSpecialist
from reporting_specialist import ReportingSpecialist

# The router only classifies intent — a light task. Run it on a cheaper model.
# Specialists do the heavy reasoning and keep the smarter model. Change freely.
ROUTER_MODEL = os.environ.get("AISOC_ROUTER_MODEL", "gpt-5.6-sol")


# --- Registry of specialists ------------------------------------------------
#
# Each specialist registers here once. The frontend and the router see them
# through this registry; nothing else changes when the roster grows.

_REGISTRY: dict[str, Specialist] = {}


def register(agent: Specialist) -> None:
    _REGISTRY[agent.name] = agent


def registry() -> dict[str, Specialist]:
    return dict(_REGISTRY)


# Register the specialists that exist today. The roster grows here; nothing
# else changes when it does.
register(EntitySpecialist())
register(TriageSpecialist())
register(IdentitySpecialist())
register(ThreatIntelSpecialist())
register(CorrelationSpecialist())
register(ReportingSpecialist())


# --- Model client (router only) --------------------------------------------

_client: AzureOpenAI | None = None


def _model_client() -> AzureOpenAI:
    global _client
    if _client is None:
        endpoint = config.require("AISOC_AOAI_ENDPOINT", config.AOAI_ENDPOINT)
        provider = get_bearer_token_provider(config.credential(), config.profile().aoai_scope)
        _client = AzureOpenAI(
            azure_endpoint=endpoint,
            azure_ad_token_provider=provider,
            api_version=config.AOAI_API_VERSION,
        )
    return _client


# --- Routing ----------------------------------------------------------------

_ROUTER_SYSTEM = """You are the router for a SOC investigation platform. Given the
analyst's request and the list of available specialists, choose the single best
specialist to handle it, or 'none' if none fit.

Return strict JSON: {"agent": "<name or none>", "reason": "<one sentence>",
"task": "<the task to hand the specialist, rephrased if helpful>"}.

Route on what the request is fundamentally about. An IP, hash, account, or host
lookup goes to the entity investigator. Do not invent specialists that are not
listed."""


def _route(message: str) -> dict[str, Any]:
    cards = [a.card() for a in _REGISTRY.values() if a.card()["available"]]
    routing_input = {
        "request": message,
        "specialists": [{"name": c["name"], "description": _REGISTRY[c["name"]].description}
                        for c in cards],
    }
    resp = _model_client().chat.completions.create(
        model=ROUTER_MODEL,
        messages=[
            {"role": "system", "content": _ROUTER_SYSTEM},
            {"role": "user", "content": json.dumps(routing_input)},
        ],
        response_format={"type": "json_object"},
    )
    try:
        return json.loads(resp.choices[0].message.content)
    except Exception:  # noqa: BLE001
        return {"agent": "none", "reason": "router returned unparseable output", "task": message}


# --- Public entry point -----------------------------------------------------

def investigate(message: str) -> dict[str, Any]:
    """Route a natural-language request to a specialist and return its result.

    Never raises. The response always includes the routing decision so the
    frontend can show which specialist handled the request.
    """
    started = time.monotonic()

    available = [a.card() for a in _REGISTRY.values() if a.card()["available"]]
    if not available:
        return {"status": "unavailable",
                "reason": "no specialist is available for this customer",
                "routing": None}

    try:
        decision = _route(message)
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "reason": f"routing failed: {exc}", "routing": None}

    name = decision.get("agent", "none")
    if name == "none" or name not in _REGISTRY:
        return {
            "status": "no_route",
            "routing": decision,
            "available_specialists": [c["name"] for c in available],
            "message": "No specialist matched this request. "
                       "Available: " + ", ".join(c["name"] for c in available),
        }

    agent = _REGISTRY[name]
    result = agent.run(decision.get("task", message))
    out = result.to_dict()
    out["routing"] = decision
    out["orchestration_seconds"] = round(time.monotonic() - started, 2)
    return out


def consult(agent_name: str, task: str, context: dict | None = None) -> dict[str, Any]:
    """Agent-to-agent call. A specialist consults another by name.

    The callee runs under its own scope and returns only its result; the caller
    never inherits the callee's privileges. This is the composition primitive
    that lets specialists collaborate without privilege escalation.
    """
    agent = _REGISTRY.get(agent_name)
    if agent is None:
        return {"status": "unavailable", "reason": f"no specialist named '{agent_name}'"}
    if not agent.card()["available"]:
        return {"status": "unavailable", "reason": f"specialist '{agent_name}' unavailable"}
    return agent.run(task, context=context).to_dict()


if __name__ == "__main__":
    import sys

    print("registered specialists:")
    for name, agent in registry().items():
        c = agent.card()
        print(f"  {name:<22} available={c['available']}  sources={len(c['sources'])}")

    if len(sys.argv) > 1:
        msg = " ".join(sys.argv[1:])
        print(f"\nrequest: {msg}\n")
        print(json.dumps(investigate(msg), indent=2, default=str))
