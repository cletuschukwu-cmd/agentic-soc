"""Incident triage specialist.

The original reference implementation, refactored onto the shared agent base so
it is a proper specialist like the entity investigator — its own declared
scope, its own tools, its own evaluation, routable by the orchestrator.

It handles an incident: given an incident number (or a request naming one), it
builds the evidence envelope, enriches, and returns a grounded verdict.
"""

import json

from agent_base import Specialist, Tool
import entity_tools as et
from envelope import build_envelope, model_view


def get_incident_envelope(incident_number: int) -> dict:
    """Resolve an incident into its evidence envelope for the agent to reason on."""
    try:
        env = build_envelope(int(incident_number))
        return {"available": True, "envelope": model_view(env)}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc)[:200]}


INCIDENT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "get_incident_envelope",
        "description": "Fetch the full evidence envelope for a Sentinel incident by its number: "
                       "incident metadata, its alerts, and normalised entities.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["incident_number"],
            "properties": {
                "incident_number": {"type": "integer", "description": "The Sentinel IncidentNumber."},
            },
        },
    },
}


class TriageSpecialist(Specialist):
    name = "incident_triage"
    # Heavy reasoning — keep the smarter model. Override via this line only.
    model = "gpt-5.6-sol"
    description = (
        "Triages a Sentinel or Defender incident by its number: assembles the "
        "incident's alerts and entities, enriches with device, identity and raw "
        "event detail, and returns a disposition (true/false/benign positive) "
        "with evidence. Use when the analyst references an incident number or "
        "asks to triage, assess, or disposition an incident."
    )

    max_rounds = 8

    allowed_sources = (
        "incidents", "alerts", "identity_info", "device_info",
        "process_events", "network_events", "file_events", "signins",
    )

    system_prompt = """You are a senior SOC analyst triaging a security incident.

First call get_incident_envelope with the incident number to load its alerts and
entities. Then investigate:
- If the envelope is thin — generic alert names, missing detail — do not settle
  for insufficient_evidence. Use describe_source and sample_source to learn the
  real schema, then deep_query to pull the actual raw events (process command
  lines, network connections, executing accounts) and analyse them.
- Weight the historical disposition of the same detection heavily if visible.

Conclude with a verdict:
- Cite evidence you actually retrieved; every key_evidence item carries a source
  table and an identifier that resolves in it. Never invent identifiers.
- Return insufficient_evidence only after genuinely drilling in, and name what
  was missing.
- Calibrate confidence honestly; reserve above 0.85 for unambiguous evidence.
- Missing a real intrusion is far worse than a wasted review. When torn, prefer
  investigate or escalate.
- Keep reasoning under 120 words.
"""

    tools = [
        Tool("get_incident_envelope", get_incident_envelope, INCIDENT_SCHEMA,
             required_sources=("incidents", "alerts")),
        Tool("describe_source", et.describe_source, et.DESCRIBE_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
        Tool("sample_source", et.sample_source, et.SAMPLE_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
        Tool("deep_query", et.deep_query, et.DEEP_QUERY_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
        Tool("lookup_account", et.lookup_account, et.ACCOUNT_SCHEMA,
             required_sources=("identity_info", "signins")),
        Tool("lookup_host", et.lookup_host, et.HOST_SCHEMA,
             required_sources=("device_info", "alerts", "process_events")),
    ]


if __name__ == "__main__":
    import sys

    agent = TriageSpecialist()
    print("agent card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])

    if len(sys.argv) > 1:
        task = " ".join(sys.argv[1:])
        print(f"\ntriaging: {task}\n")
        print(json.dumps(agent.run(task).to_dict(), indent=2, default=str))
