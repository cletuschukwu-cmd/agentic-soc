"""Agent base — the contract every specialist implements.

This is where the platform's security guarantees are enforced structurally,
not by convention. A specialist declares, up front, the exact set of logical
sources it may touch. The base refuses any tool call that reaches outside that
set — so a specialist cannot exceed its declared scope even if its prompt is
manipulated or its own code has a bug. Least privilege is a property of the
architecture, not a promise in a system prompt.

Every specialist gets:
  * a name and description the orchestrator routes on
  * an allowed_sources allowlist (logical source names) — its blast radius
  * a system prompt
  * a scoped tool set, filtered to only the tools its sources permit
  * a structured, grounded result via the shared verdict contract
  * an audit record of every source it touched

A specialist NEVER holds write or containment capability. Every agent in this
platform is read-and-reason only; state-changing actions live behind explicit
human approval outside the agent layer.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from openai import AzureOpenAI
from azure.identity import get_bearer_token_provider

import config
import contracts
import injection_guard
import sources
from envelope import run_kql


# --- Shared model client ----------------------------------------------------

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


# --- Tool descriptor --------------------------------------------------------

@dataclass(frozen=True)
class Tool:
    """A capability a specialist can invoke.

    `required_sources` ties the tool to logical sources. The base grants the
    tool to a specialist only if the specialist's allowed_sources covers the
    tool's required_sources — so scoping the agent automatically scopes its
    tools. `fn` executes; `schema` is the JSON contract given to the model.
    """
    name: str
    fn: Callable[..., dict]
    schema: dict
    required_sources: tuple[str, ...] = ()


# --- Result -----------------------------------------------------------------

@dataclass
class AgentResult:
    status: str                      # ok | unavailable
    agent: str
    verdict: dict | None = None
    grounding: dict | None = None
    sources_touched: list[str] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    injection_findings: list[dict] = field(default_factory=list)
    latency_seconds: float = 0.0
    reason: str = ""
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "agent": self.agent,
            "verdict": self.verdict,
            "grounding": self.grounding,
            "sources_touched": self.sources_touched,
            "tool_calls": self.tool_calls,
            "injection_findings": self.injection_findings,
            "latency_seconds": round(self.latency_seconds, 2),
            "reason": self.reason,
            "model_deployment": self.model or config.MODEL_DEPLOYMENT,
        }


# --- Specialist base --------------------------------------------------------

class Specialist:
    """Base class for every specialist agent.

    Subclasses set: name, description, allowed_sources, system_prompt, and the
    list of Tool objects they offer. The base handles scoping enforcement, the
    tool-calling loop, grounding verification, the audit trail, and fail-open
    behaviour. Subclasses contain no orchestration logic — only their prompt,
    their sources, and their tools.
    """

    name: str = "specialist"
    description: str = ""
    allowed_sources: tuple[str, ...] = ()
    system_prompt: str = ""
    tools: list[Tool] = []
    max_rounds: int = 6
    # Per-agent model. None -> fall back to the global default (config.MODEL_DEPLOYMENT).
    # Specialists do the heavy reasoning, so they get the smarter model; the
    # orchestrator, which only routes, can run a cheaper one. Change freely.
    model: str | None = None

    # Output contract. Default: the structured verdict every investigative
    # specialist produces. A specialist whose output is not a verdict (e.g. a
    # report) overrides this and sets verdict_output = False so the base does
    # not run citation grounding against a non-verdict shape.
    response_format: dict | None = None   # None -> contracts.RESPONSE_FORMAT
    verdict_output: bool = True

    def _model(self) -> str:
        return self.model or config.MODEL_DEPLOYMENT

    def _response_format(self) -> dict:
        return self.response_format or contracts.RESPONSE_FORMAT

    # -- scoping enforcement --------------------------------------------------

    def _authorized_tools(self) -> list[Tool]:
        """Only tools whose required sources fall within this agent's scope AND
        are actually available for the customer. This is the structural
        least-privilege gate."""
        allowed = set(self.allowed_sources)
        out = []
        for t in self.tools:
            if not set(t.required_sources).issubset(allowed):
                continue  # tool reaches outside this agent's declared blast radius
            if any(not sources.has(s) for s in t.required_sources):
                continue  # a required source is unavailable for this customer
            out.append(t)
        return out

    def _assert_source(self, logical: str) -> None:
        if logical not in self.allowed_sources:
            raise PermissionError(
                f"agent '{self.name}' attempted to use source '{logical}' "
                f"outside its declared scope {self.allowed_sources}"
            )

    # -- execution ------------------------------------------------------------

    def _source_briefing(self) -> str:
        """Tell the agent its real, available source vocabulary so it queries
        the right logical names instead of guessing ones that don't exist."""
        usable = [s for s in self.allowed_sources if sources.has(s)]
        unusable = [s for s in self.allowed_sources if not sources.has(s)]
        lines = [
            "Your available logical sources for this customer (use these exact "
            "names with deep_query, describe_source, sample_source):",
            "  " + ", ".join(usable) if usable else "  (none available)",
        ]
        if unusable:
            lines.append(
                "Declared but NOT available for this customer (do not query these): "
                + ", ".join(unusable))
        lines.append("Do not invent source names outside this list; they will fail.")
        return "\n".join(lines)

    def run(self, task: str, context: dict | None = None) -> AgentResult:
        """Investigate `task`. Never raises; failures return status=unavailable."""
        started = time.monotonic()
        touched: list[str] = []
        trace: list[dict] = []
        injection_findings: list[dict] = []

        authorized = self._authorized_tools()
        schemas = [t.schema for t in authorized]
        dispatch = {t.name: t for t in authorized}

        content = task
        if context:
            content = f"Context:\n{json.dumps(context, default=str)}\n\nTask: {task}"
        messages = [
            {"role": "system", "content": self.system_prompt + "\n\n" + self._source_briefing()},
            {"role": "user", "content": content},
        ]

        try:
            for round_i in range(self.max_rounds):
                budget_spent = time.monotonic() - started
                # When the budget is nearly gone, stop investigating and force a
                # verdict from what has been gathered, rather than getting killed
                # mid-investigation and losing everything.
                if budget_spent > config.AGENT_BUDGET_SECONDS * 0.8:
                    messages.append({
                        "role": "user",
                        "content": "You are out of investigation time. Do not call any "
                                   "more tools. Return your verdict now based on the "
                                   "evidence gathered so far; lower confidence and list "
                                   "what remained unchecked in unavailable_context.",
                    })
                    break

                resp = _model_client().chat.completions.create(
                    model=self._model(),
                    messages=messages,
                    tools=schemas or None,
                    tool_choice="auto" if schemas else "none",
                )
                msg = resp.choices[0].message
                if not msg.tool_calls:
                    messages.append({"role": "assistant", "content": msg.content or ""})
                    break

                messages.append(msg.model_dump(exclude_none=True))
                for call in msg.tool_calls:
                    tool = dispatch.get(call.function.name)
                    trace.append({"tool": call.function.name, "args": call.function.arguments})
                    if tool is None:
                        result = {"available": False,
                                  "reason": "tool not authorized for this agent"}
                    else:
                        try:
                            args = json.loads(call.function.arguments or "{}")
                            result = tool.fn(**args)
                            for s in tool.required_sources:
                                if s not in touched:
                                    touched.append(s)
                        except Exception as exc:  # noqa: BLE001
                            result = {"available": False, "reason": str(exc)[:200]}
                    # Scan tool output for prompt-injection before it reaches the
                    # model. Warn, never strip: flagged content stays visible so
                    # the agent can analyse it and report the manipulation attempt.
                    _, findings = injection_guard.annotate(result)
                    payload = json.dumps(result, default=str)[:8000]
                    if findings:
                        for f in findings:
                            if f not in injection_findings:
                                injection_findings.append(f)
                        banner = injection_guard.warning_banner(findings)
                        content_out = (
                            banner
                            + "\n\n--- untrusted evidence follows ---\n"
                            + payload
                        )
                    else:
                        content_out = payload
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": content_out,
                    })

            messages.append(
                {"role": "user", "content": ("Now return the report object and nothing else."
                                             if not self.verdict_output else
                                             "Now return the verdict object and nothing else.")}
            )
            final = _model_client().chat.completions.create(
                model=self._model(),
                messages=messages,
                response_format=self._response_format(),
            )
            verdict = json.loads(final.choices[0].message.content)
        except Exception as exc:  # noqa: BLE001
            return AgentResult("unavailable", self.name, reason=str(exc)[:300],
                               sources_touched=touched, tool_calls=trace,
                               injection_findings=injection_findings, model=self._model(),
                               latency_seconds=time.monotonic() - started)

        grounding = contracts.verify_citations(verdict, run_kql) if self.verdict_output else None
        return AgentResult(
            "ok", self.name, verdict=verdict, grounding=grounding,
            sources_touched=touched, tool_calls=trace,
            injection_findings=injection_findings, model=self._model(),
            latency_seconds=time.monotonic() - started,
        )

    # -- description for the orchestrator ------------------------------------

    def card(self) -> dict[str, Any]:
        """What the orchestrator sees when deciding whether to route here."""
        return {
            "name": self.name,
            "description": self.description,
            "sources": list(self.allowed_sources),
            "available": all(sources.has(s) for s in self.allowed_sources) if self.allowed_sources else True,
        }
