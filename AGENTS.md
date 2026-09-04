# Agent Roster

The multi-agent design at a glance. Refresh your memory by opening this file.
Marked by status so you always know what is real versus planned.

Status: **BUILT** = working today · **PLANNED** = designed, not yet built

---

## How the agents communicate

There is no agent-to-agent magic. Communication is explicit code you own
(required, because Foundry's agent-to-agent is unavailable in Azure Government).

```
                 analyst question (natural language)
                              |
                              v
                     +------------------+
                     |   ORCHESTRATOR   |   reads intent, picks ONE specialist
                     |   (router)       |   (uses the model to route)
                     +------------------+
                        |    |    |    |
            routes to one specialist based on the request
                        |    |    |    |
        +---------------+    |    |    +-----------------+
        v                    v    v                      v
   +----------+      +-------------+   +-----------+   ... more specialists
   | TRIAGE   |      |   ENTITY    |   | (planned) |
   +----------+      +-------------+   +-----------+
        |                    |
   each specialist runs UNDER ITS OWN SCOPE (allowed_sources fixed in code),
   calls only its authorized tools, returns a grounded verdict
        |                    |
        v                    v
              structured verdict back to the analyst
```

Two communication paths:

1. **Orchestrator -> specialist** (`orchestrator.investigate`). The router reads
   the analyst's request, picks the best-fit specialist, hands it the task. This
   is the normal path.

2. **Specialist -> specialist** (`orchestrator.consult`) — PLANNED in use. One
   specialist asks another for help mid-investigation (e.g. entity investigation
   escalating a suspicious account to the identity specialist). The primitive
   EXISTS in code; no specialist calls it yet because the identity specialist
   isn't built. Key rule: the caller NEVER inherits the callee's privileges —
   the callee runs under its own scope. That is how least-privilege survives
   agents calling agents.

Every agent is **read-and-reason only**. None can change, close, or contain
anything. State-changing actions live outside the agent layer behind human
approval.

---

## The agents

### Orchestrator (router) — BUILT
- **File:** `orchestrator.py`
- **Task:** Read the analyst's natural-language request, decide which specialist
  should handle it, dispatch, return the result with the routing decision shown.
- **Not a specialist itself** — it holds no sources, does no investigation. It
  routes and composes.
- **Known risk:** the routing decision is an unguarded AI choice (Risk R7). A
  misroute sends the request to the wrong specialist. Router accuracy is not yet
  measured.

### 1. Incident Triage — BUILT
- **File:** `triage_specialist.py`
- **Task:** Triage a Sentinel/Defender incident by number. Loads the incident's
  alerts and entities, enriches with device/identity/raw-event detail, returns a
  disposition (true / false / benign positive) with evidence.
- **Scope (allowed_sources):** incidents, alerts, identity_info, device_info,
  process_events, network_events, file_events, signins.
- **Routes here when:** the request names an incident number or asks to triage /
  assess / disposition an incident.

### 2. Entity Investigator — BUILT
- **File:** `entity_specialist.py`
- **Task:** Investigate a single indicator — IP, file hash, account, or host —
  across network, endpoint, identity, and threat-intel evidence. Fast curated
  lookup first; drills into raw events (with schema inspection) only when needed.
- **Scope (allowed_sources):** network_events, process_events, file_events,
  identity_info, signins, device_info, alerts, threat_intel.
- **Routes here when:** the request is about an IP, hash, account, or host.

### 3. Identity-Compromise Specialist — PLANNED
- **Task:** Investigate whether an account is compromised. Sign-in patterns,
  impossible travel, privilege, risk state, PIM activations, MFA anomalies.
- **Likely scope:** signins, noninteractive_signins, identity_info, audit,
  alerts.
- **Value:** first specialist another specialist would consult (entity finds a
  suspicious account -> asks this one for a deep identity assessment).

### 4. Detection-Tuning / Incident-Summary — PLANNED
- **Task:** Analyst-facing reporting. Summarize incidents of a type over a
  window; mine closure/alert data for noisy rules and false-positive patterns.
- **Likely scope:** incidents, alerts.
- **Value:** the "summarize all my false-positive incidents this month" ask that
  currently returns no_route.

### 5. Threat-Intel Specialist — PLANNED
- **Task:** CVE and IOC lookup, exposure questions ("are we affected by X"),
  reputation. Gov-compatible: reads a pre-ingested feed, not the live web.
- **Likely scope:** threat_intel (+ external feeds via the source registry).
- **Note:** your lab has ThreatIntelIndicators (1.5M rows) — real data exists.

### 6. Data-Security Specialist — PLANNED
- **Task:** Sensitive-data exposure and classification. "What data was at risk"
  when a store or share is accessed anomalously. Highest differentiation, hardest
  to build. Depends on Purview scanner coverage.
- **Likely scope:** storage sources + Purview classification (via the registry's
  storage kind, not yet implemented).
- **Security note:** an agent that can read sensitive content is itself a target
  — content retrieval must be gated and logged as privileged.

---

## The shared foundation every agent stands on (all BUILT)

- `agent_base.py` — the contract: fixed per-agent scope, tool filtering to that
  scope, the tool-calling loop, grounding verification, injection scanning, the
  audit trail (sources_touched), fail-open behaviour, budget discipline.
- `sources.py` — source registry: logical capability -> real transport (kql now;
  storage / rest_api / file planned). Enforces Gov mode governance.
- `schema.py` — per-customer schema discovery + discover-then-approve gate.
- `injection_guard.py` — scans tool output for prompt-injection; warns, never
  strips.
- `contracts.py` — the verdict schema + citation verification (groundedness).
- `eval_harness.py` — measures a specialist against known-answer cases
  (evolving toward the production-truth model; see RISK_REGISTER R3).

---

## Build order (from here)

1. Truth-anchored evaluation — establish real effectiveness (in progress).
2. Frontend — the analyst console (promptbooks land here).
3. Remaining specialists — identity, detection-summary, threat-intel, data.
4. Risk remediation — per RISK_REGISTER priority order.
