# AI SOC triage — 14-day proof of value

A single triage agent over a Sentinel evidence envelope, backtested against
analyst closure decisions. Built to run unchanged in Azure commercial and
Azure Government.

## Portability decisions, and why

| Decision | Reason |
| --- | --- |
| Direct Azure OpenAI, not Foundry Agent Service | The Foundry portal's IL4/IL5 audit scope is uncertain; Azure OpenAI is in scope. Verify against the current audit-scope matrix. |
| Function calling with plain functions | MCP servers and the OpenAPI tool are unavailable in Azure Government. |
| Orchestration loop in `agent.py` | Hosted agents and agent-to-agent are unavailable in Gov. |
| Backtest harness as customer code | Foundry Evaluations is listed unavailable in Gov, and your metrics are custom anyway. |
| Model pinned via env var | Gov trails commercial by several model releases. Pin to the newest model in **both**. |
| All endpoints in `config.py` | Switching clouds is one environment variable. |

Verify the Gov availability tables yourself before committing — they change,
and two documents I was shown disagreed about MCP.

## Setup

```bash
pip install -r requirements.txt
az login                      # az cloud set --name AzureUSGovernment first, for Gov

export AISOC_CLOUD=commercial
export AISOC_WORKSPACE_ID="<log-analytics-workspace-guid>"
export AISOC_AOAI_ENDPOINT="https://<resource>.openai.azure.com/"
export AISOC_MODEL_DEPLOYMENT="gpt-51-triage"
```

RBAC for the identity running this: **Log Analytics Reader** on the workspace
and **Cognitive Services OpenAI User** on the Azure OpenAI resource. Read-only
throughout — nothing here writes.

## Order of operations

```bash
python backtest.py --baseline          # 1. no AI: which rules dominate, and their FP rates
python agent.py 12345                  # 2. one incident end to end
python backtest.py --limit 60          # 3. the actual measurement
python backtest.py --report results.json
```

Step 1 on day one. It is a real deliverable on its own, it takes an afternoon,
and it tells you whether the rest is worth building.

## Day by day

**1–2** Baseline queries. Pick the two or three detections the PoV covers.
Confirm auth to Log Analytics and Azure OpenAI works — do this as a spike now,
not on day five. Write down your success threshold before you see any results.

**3–5** Evidence envelope. `parse_entities` is where this slips; the
`Entities` blob differs by detection product. Only handle the entity types
your chosen detections actually emit.

**6–7** Agent and prompt iteration against a handful of incidents.

**8–9** Full backtest. Read every disagreement by hand.

**10–11** Live path in shadow: write the verdict as a Sentinel incident
comment and tag. Change no routing and no severity.

**12–13** Workbook over the verdict table. Buffer for what breaks.

**14** Demo.

## If the lab has no incident history

A greenfield lab has no closures, so there is no ground truth. In order of
preference: seed with the Sentinel Training Lab solution from Content Hub;
generate real telemetry with Defender XDR attack simulation; or hand-label
constructed scenarios.

Say plainly in the demo that the eval set is manufactured. The honest framing
is stronger anyway: the harness is the deliverable, the lab numbers are
illustrative, and the same harness runs unchanged against real closures the
day it lands in a tenant with history.

## What to report

Four numbers, not one:

- **Agreement rate** with analyst classifications
- **True positive recall** — the number that matters; set this as your
  threshold on day one and hold to it even at the cost of precision
- **Groundedness** — the fraction of cited identifiers that actually resolve,
  computed by `contracts.verify_citations`, not asserted
- **Insufficient-evidence rate** — where your enrichment is thin

Plus median latency and cost per incident. Someone will ask.

## Demo structure

1. The baseline: this rule fired N times, analysts closed X% as false
   positive, median Y minutes each.
2. One incident end to end — raw alert versus enriched verdict with its
   evidence chain.
3. Aggregate backtest numbers.
4. Two disagreements, honestly presented, including one where the agent was
   wrong and why.

Point 4 is what makes it credible to a room of security people. A proof of
value claiming no errors gets disbelieved.

## What this is not, yet

No writeback, no correlation store, no severity changes, no auto-close. Those
are right for production and they are scope you cannot afford in two weeks.

## Where it goes next

Every differentiator worth having is downstream of the envelope and the
verdict contract already here:

- **Institutional memory** — an AI Search index over resolved incidents, so
  the agent can say "we have seen this eleven times, here is what it was."
  `get_rule_history` is the crude first version.
- **Customer context** — CMDB, change windows, exception register, crown-jewel
  inventory. More fields in the envelope. This is the deepest advantage,
  because no off-the-shelf product knows any of it.
- **Shift handoff and timeline** — a second prompt over the same envelope,
  roughly half a day each.
- **Data sensitivity** — a Purview-fed lookup, once scanner coverage exists.
