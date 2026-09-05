"""Threat-intelligence enrichment specialist.

Takes indicators — IPs, file hashes, domains, URLs — and checks them against
known-bad intelligence, adding external corroboration that sharpens other
verdicts. Today over the ingested ThreatIntelIndicators table; external feeds
later via the source registry.

Discipline: no intel match is NOT a safety signal (Risk R4). Novel/targeted
indicators no feed has seen return nothing here. This specialist says
"no known-bad match" and lets absence stay absence.
"""

from agent_base import Specialist, Tool
import threatintel_tools as ti


class ThreatIntelSpecialist(Specialist):
    name = "threat_intel"
    model = "gpt-5.6-sol"
    max_rounds = 6

    description = (
        "Checks indicators — IP addresses, file hashes, domains, URLs — against "
        "known-bad threat intelligence, and answers reputation and campaign "
        "questions. Use for 'is this hash/IP/domain malicious', 'is this a known "
        "C2', 'is this indicator in our threat intel', 'anything from campaign X'. "
        "Adds external corroboration; does not analyse your own telemetry."
    )

    allowed_sources = ("threat_intel",)

    system_prompt = """You are a threat-intelligence analyst. Given one or more
indicators, determine whether they are known bad according to available
intelligence.

- For a single indicator, use lookup_indicator. For several from one incident,
  use lookup_indicators_bulk — multiple known-bad matches from the same incident
  indicate a coordinated attack, which is a strong signal.
- Use search_by_tag for campaign/family/actor questions.
- Weigh confidence and validity. A high-confidence, currently-valid match is
  strong; a low-confidence or expired one is weak.

Critical: a "no match" result means the indicator is NOT KNOWN BAD — it does NOT
mean the indicator is safe. Novel and targeted indicators no feed has seen
return nothing. Never conclude benign from absence of intel. Say "no known-bad
intelligence match" and, if that's all you have, return likely_benign only when
paired with that explicit caveat, otherwise insufficient_evidence.

Conclude with a verdict:
- Cite the intel you retrieved. If a match exists, cite the ObservableValue.
- Calibrate confidence to the intel confidence and recency.
- Keep reasoning under 120 words.
"""

    tools = [
        Tool("lookup_indicator", ti.lookup_indicator, ti.INDICATOR_SCHEMA,
             required_sources=("threat_intel",)),
        Tool("lookup_indicators_bulk", ti.lookup_indicators_bulk, ti.BULK_SCHEMA,
             required_sources=("threat_intel",)),
        Tool("search_by_tag", ti.search_by_tag, ti.TAG_SCHEMA,
             required_sources=("threat_intel",)),
    ]


if __name__ == "__main__":
    import json, sys
    agent = ThreatIntelSpecialist()
    print("card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])
    if len(sys.argv) > 1:
        print(json.dumps(agent.run(" ".join(sys.argv[1:])).to_dict(), indent=2, default=str))
