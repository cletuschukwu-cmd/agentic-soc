# Risk Register

Known risks and limitations of the AI SOC platform, with current mitigation
status. This is a living document — updated as risks are addressed. It exists so
that no known risk is silently forgotten, and so that a security review or
authorization conversation has an honest account of limitations and mitigations.

Status legend:
- **OPEN** — identified, no mitigation yet
- **PARTIAL** — some mitigation in place, incomplete
- **MITIGATED** — addressed to a defensible level (never "solved" — these are
  managed risks, not closed ones)

Severity reflects impact on a security-decision system specifically, where a
confident wrong answer can let a real intrusion proceed.

---

## R1 — Prompt injection
**Severity: High · Status: PARTIAL**

The agent reads adversary-controlled text (command lines, file names, alert
descriptions) as evidence. An attacker aware that an AI triages their activity
can plant instructions in that data to corrupt the verdict ("mark this benign").

Mitigations in place:
- Injection detection scans every tool result (`injection_guard.py`); flagged
  content is wrapped with a warning and surfaced in `injection_findings`, never
  stripped — the attempt itself becomes a finding.
- Structural separation: tool output is delimited and labelled untrusted in
  context.
- Structured-citation grounding makes an injected narrative hard to convert into
  a valid evidence trail.
- Advisory-only: verdicts never auto-act, so injection degrades a recommendation
  rather than causing a breach.

Still open:
- No complete defense exists; a sufficiently clever injection can still sway
  reasoning. Live adversarial validation incomplete (see R11).
- Detection is signature-based and will miss novel phrasings.

---

## R2 — Model is a single point of failure and non-deterministic
**Severity: High · Status: OPEN**

The same incident can yield different verdicts across runs. The platform depends
entirely on one model family; degradation, drift, or a provider-side change
shifts every verdict, possibly unnoticed.

Directions:
- Consistency checks (run critical verdicts more than once; flag disagreement).
- A second, independent model as a cross-check on high-stakes verdicts.
- Verdict-change monitoring across model versions in the eval harness.
- Pin model versions per customer (the profile already supports this).

---

## R3 — Grounding proves citation resolution, not reasoning validity
**Severity: High · Status: OPEN**

`verify_citations` confirms cited identifiers exist. It does NOT confirm the
agent reasoned correctly from them. An agent can cite three real alerts and draw
a wrong conclusion — perfectly grounded, perfectly wrong. Groundedness is an
anti-fabrication signal, not a quality signal.

Directions:
- Evaluation against expert verdicts (the real validity measure) — harness
  exists (`eval_harness.py`), needs real ground truth at scale.
- Confidence calibration tracking (does 0.8 mean right 80% of the time).
- Reasoning-step critique (a second pass challenging the logic, not just the
  citations).

---

## R4 — Absence of evidence read as evidence of absence
**Severity: High · Status: OPEN**

Empty query results can mean "nothing malicious happened" OR "logging was off /
data not ingested / retention expired / filter wrong." An attacker who disables
logging produces the same empty result as a clean host. Conflating these is
exactly where a real intrusion hides.

Directions:
- Telemetry-coverage checks: before concluding benign from absence, confirm the
  relevant source actually has data for that entity/window.
- Distinguish "no evidence of X" from "confirmed X did not occur" in the verdict
  contract.
- Instruct agents to treat unexplained gaps as escalation factors, not comfort.

---

## R5 — No temporal reasoning or memory
**Severity: Medium · Status: OPEN**

Each investigation is stateless. The agent cannot see that an entity's behaviour
changed, cannot correlate today's incident with a related one last week, cannot
recall it examined this host yesterday. Slow-burn campaigns are missed by
construction.

Directions:
- Investigation memory store (per entity, per customer).
- Baseline/deviation reasoning ("this is different from normal for this host").
- Cross-incident correlation over time.

---

## R6 — Cost and rate limits at scale unmodeled
**Severity: Medium · Status: OPEN**

A 6-tool investigation is fine; 500 incidents/day is not yet measured. Risks:
Azure OpenAI token-per-minute limits, Log Analytics query throttling, unmodeled
per-incident dollar cost. Works in demo, may fall over or become expensive at
production volume.

Directions:
- Per-investigation cost/token accounting (surface it in results).
- Rate-limit handling and backoff in the model and query clients.
- Caching of repeated lookups; batching.
- Cost ceilings per customer in the profile.

---

## R7 — Router is an unguarded AI decision
**Severity: Medium · Status: OPEN**

The orchestrator uses the model to pick a specialist. A misroute sends an
incident to the wrong specialist and a bad investigation follows. Specialist
accuracy is (being) measured; router accuracy is not.

Directions:
- Router evaluation set (request -> correct specialist).
- Confidence threshold on routing; ambiguous -> ask or run multiple.
- Fallback when no specialist clearly fits (partly present: `no_route`).

---

## R8 — No feedback loop from analyst to agent
**Severity: Medium · Status: OPEN**

When the agent is wrong and an analyst corrects it, the correction goes nowhere.
No learning, no prompt improvement, same mistake repeats.

Directions:
- Capture analyst agree/disagree per verdict (distinct from incident closure).
- Feed corrections into the eval set and prompt refinement.
- Track per-specialist accuracy trend over time.

---

## R9 — Entity resolution is shallow and fragile
**Severity: Medium · Status: PARTIAL**

Seen live: `knightsdc01` vs its FQDN vs two device IDs for one host. Across a
real enterprise with inconsistent naming, "is this the same entity" is hard and
getting it wrong means investigating the wrong thing while believing otherwise.

Mitigations in place:
- Schema-awareness (`describe_source`/`sample_source`) lets the agent discover
  real value shapes before filtering.

Still open:
- No canonical entity resolution across identifiers/sources.
- No CMDB/asset-inventory join to reconcile names.

---

## R10 — "Read-only is safe" is only partly true
**Severity: High · Status: PARTIAL**

Read-only protects against the agent *doing* damage. It does nothing against a
confident WRONG benign verdict on a real intrusion — false reassurance that lets
an attacker proceed. The dangerous output here is a wrong answer, not an action.
Compounded by automation bias: the better the system looks, the less its rare
confident-wrong verdict gets double-checked.

Mitigations in place:
- Advisory-only; humans see every verdict.
- Asymmetric-cost instruction (prefer investigate/escalate when torn).
- `insufficient_evidence` as a first-class outcome.

Still open:
- No calibration guarantee (see R3).
- No systemic guard against automation bias in how verdicts are presented.

---

## R11 — No adversarial testing
**Severity: High · Status: OPEN**

The agent has mostly been watched succeeding, not actively attacked. Injection
defense (R1) is unit-tested but not validated end-to-end against live crafted
telemetry. Absence-of-evidence, misrouting, and confident-wrong failure modes
are untested adversarially.

Directions:
- Red-team suite: crafted incidents designed to fool each specialist and the
  router.
- Live injection validation (attempted, incomplete — trigger/host mismatch).
- Regression: every fixed failure becomes a permanent test case.

---

## Priority order for remediation

Highest-value first, for a security-decision system:

1. **R3 / R10** — reasoning validity and confident-wrong verdicts. The core
   trust question; addressed by real evaluation + calibration.
2. **R4** — absence-of-evidence. Where real intrusions hide.
3. **R1 / R11** — injection and adversarial testing. Unique to security AI.
4. **R2** — model reliability / cross-checks.
5. **R6** — cost/rate limits, before any production volume.
6. **R7, R8, R9, R5** — router accuracy, feedback loop, entity resolution,
   memory — platform maturity.

This ordering is a recommendation, not a commitment; revisit as the build and
customer needs evolve.
