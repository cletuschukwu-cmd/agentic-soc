"""Triage agent.

A single agent with sequential tool calls, orchestrated here rather than by a
managed agent runtime. That is a deliberate portability decision: hosted
agents and agent-to-agent are unavailable in Azure Government, so the
orchestration loop lives in code you own and runs unchanged in either cloud.

It also fails open. If the model or a tool is unavailable, callers get a
verdict object with status 'unavailable' rather than an exception, so an
enrichment step in a live alert path can never block alerts from flowing.
"""

import json
import time
from typing import Any

from openai import AzureOpenAI
from azure.identity import get_bearer_token_provider

import config
import contracts
import tools
from envelope import build_envelope, model_view, run_kql

SYSTEM_PROMPT = """You are a senior SOC analyst triaging a security incident.

You are given an evidence envelope and a set of read-only tools. Investigate,
then return a single verdict conforming to the schema.

How to work:
- Always call get_rule_history first. How analysts have historically closed
  this same detection is strong prior evidence and is often decisive.
- Enrich every account and device entity that appears material. Privilege,
  risk state and sign-in patterns change the answer more than alert names do.
- Use run_scoped_kql when you need something the specific tools do not cover.
- Stop investigating once further calls would not change the verdict.

How to conclude:
- Cite evidence you actually retrieved. Every key_evidence item must carry a
  source table and an identifier that resolves in that table. Never invent an
  identifier. If you cannot cite it, do not claim it.
- Return insufficient_evidence when the available context genuinely does not
  support a conclusion, and list what was missing in unavailable_context.
  This is a correct answer, not a failure.
- Calibrate confidence honestly. Reserve values above 0.85 for cases where the
  evidence is unambiguous.
- Weight the cost of errors asymmetrically. Missing a real intrusion is far
  worse than sending a benign incident for review. When genuinely torn between
  likely_benign and likely_true_positive, prefer investigate.
- Keep reasoning under 120 words and state what drove the decision rather than
  restating the alert.
"""

OPEN_SYSTEM_PROMPT = """You are a senior SOC analyst assisting an analyst who is
investigating through a console. The analyst asks in natural language — about an
incident, an IP, a file hash, an account, a host, or a class of incidents over a
time window.

You have read-only tools over the security workspace. Decide which to call, then
answer.

How to work:
- Interpret the request and gather evidence with the tools before concluding.
  For an entity (IP, hash, account, host), look it up. For "summarize incidents
  of type X", query and aggregate. For an incident, enrich it.
- Use run_scoped_kql for anything the specific tools do not cover. Keep queries
  scoped and within the allowed tables.
- Stop once further calls would not change the answer.

How to conclude:
- Cite evidence you actually retrieved. Every key_evidence item carries a source
  table and an identifier that resolves in that table. Never invent identifiers.
- Return insufficient_evidence when the data does not support a conclusion, and
  say what was missing.
- Calibrate confidence honestly; reserve above 0.85 for unambiguous evidence.
- Weight errors asymmetrically: missing a real threat is worse than a false
  alarm. When torn, prefer investigate.
- Keep reasoning under 120 words.
"""

_client: AzureOpenAI | None = None


def client() -> AzureOpenAI:
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


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "reason": reason[:300],
        "verdict": None,
    }


def triage(envelope: dict, max_tool_rounds: int = 6) -> dict[str, Any]:
    """Run the agent over one envelope. Never raises."""
    started = time.monotonic()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "Evidence envelope:\n" + json.dumps(model_view(envelope), default=str),
        },
    ]
    trace: list[dict[str, Any]] = []

    try:
        for _ in range(max_tool_rounds):
            if time.monotonic() - started > config.AGENT_BUDGET_SECONDS:
                return _unavailable("agent time budget exceeded")

            resp = client().chat.completions.create(
                model=config.MODEL_DEPLOYMENT,
                messages=messages,
                tools=tools.TOOL_SCHEMAS,
                tool_choice="auto",
            )
            msg = resp.choices[0].message
            if not msg.tool_calls:
                messages.append({"role": "assistant", "content": msg.content or ""})
                break

            messages.append(msg.model_dump(exclude_none=True))
            for call in msg.tool_calls:
                name = call.function.name
                try:
                    args = json.loads(call.function.arguments or "{}")
                    result = tools.DISPATCH[name](**args)
                except Exception as exc:  # noqa: BLE001
                    result = {"available": False, "reason": str(exc)[:200]}
                trace.append({"tool": name, "args": call.function.arguments})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result, default=str)[:8000],
                    }
                )

        messages.append(
            {"role": "user", "content": "Now return the verdict object and nothing else."}
        )
        final = client().chat.completions.create(
            model=config.MODEL_DEPLOYMENT,
            messages=messages,
            response_format=contracts.RESPONSE_FORMAT,
        )
        verdict = json.loads(final.choices[0].message.content)
    except Exception as exc:  # noqa: BLE001 - fail open
        return _unavailable(str(exc))

    grounding = contracts.verify_citations(verdict, run_kql)
    return {
        "status": "ok",
        "verdict": verdict,
        "grounding": grounding,
        "tool_calls": trace,
        "latency_seconds": round(time.monotonic() - started, 2),
        "model_deployment": config.MODEL_DEPLOYMENT,
        "prompt_version": "triage-1.0",
    }


def triage_incident(incident_number: int) -> dict[str, Any]:
    try:
        env = build_envelope(incident_number)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"envelope build failed: {exc}")
    result = triage(env)
    result["incident_number"] = incident_number
    return result


def investigate_stream(user_message: str, envelope: dict | None = None):
    """Streaming investigation for the console.

    Yields dict events as the agent works, so the frontend can show reasoning
    live rather than a blank wait:
        {"type": "tool_call",  "name": ..., "args": ...}
        {"type": "tool_result","name": ..., "summary": ...}
        {"type": "verdict",    "verdict": {...}, "grounding": {...}}
        {"type": "error",      "reason": ...}

    A free-text message drives the investigation; an optional envelope seeds
    it with incident context. Never raises — errors are yielded as events.
    """
    import time as _time

    started = _time.monotonic()
    system = SYSTEM_PROMPT if envelope else OPEN_SYSTEM_PROMPT
    content = user_message
    if envelope is not None:
        content = (
            "Incident context:\n"
            + json.dumps(model_view(envelope), default=str)
            + f"\n\nAnalyst request: {user_message}"
        )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": content},
    ]

    try:
        for _ in range(8):
            if _time.monotonic() - started > config.AGENT_BUDGET_SECONDS:
                yield {"type": "error", "reason": "time budget exceeded"}
                return

            resp = client().chat.completions.create(
                model=config.MODEL_DEPLOYMENT,
                messages=messages,
                tools=tools.TOOL_SCHEMAS,
                tool_choice="auto",
            )
            msg = resp.choices[0].message
            if not msg.tool_calls:
                messages.append({"role": "assistant", "content": msg.content or ""})
                break

            messages.append(msg.model_dump(exclude_none=True))
            for call in msg.tool_calls:
                name = call.function.name
                yield {"type": "tool_call", "name": name, "args": call.function.arguments}
                try:
                    args = json.loads(call.function.arguments or "{}")
                    result = tools.DISPATCH[name](**args)
                    rc = result.get("row_count", result.get("available"))
                    yield {"type": "tool_result", "name": name, "summary": rc}
                except Exception as exc:  # noqa: BLE001
                    result = {"available": False, "reason": str(exc)[:200]}
                    yield {"type": "tool_result", "name": name, "summary": "error"}
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result, default=str)[:8000],
                    }
                )

        messages.append(
            {"role": "user", "content": "Now return the verdict object and nothing else."}
        )
        final = client().chat.completions.create(
            model=config.MODEL_DEPLOYMENT,
            messages=messages,
            response_format=contracts.RESPONSE_FORMAT,
        )
        verdict = json.loads(final.choices[0].message.content)
        grounding = contracts.verify_citations(verdict, run_kql)
        yield {
            "type": "verdict",
            "verdict": verdict,
            "grounding": grounding,
            "latency_seconds": round(_time.monotonic() - started, 2),
            "model_deployment": config.MODEL_DEPLOYMENT,
        }
    except Exception as exc:  # noqa: BLE001
        yield {"type": "error", "reason": str(exc)[:300]}


if __name__ == "__main__":
    import sys

    print(json.dumps(triage_incident(int(sys.argv[1])), indent=2, default=str))
