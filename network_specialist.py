"""Network / C2 specialist.

Determines whether a host is communicating maliciously — beaconing to C2,
contacting known-bad destinations, or repeatedly hitting blocked domains. The
first specialist to use two transports: KQL network events for behaviour, and
the Defender indicator API (rest_api) for known-bad reputation.

The two-signal correlation is its power: a host beaconing to a newly-seen
destination AND contacting an IP on the Defender indicator list is active C2,
not noise. Consultable by the correlation specialist.
"""

from agent_base import Specialist, Tool
import network_tools as nt


class NetworkSpecialist(Specialist):
    name = "network_investigator"
    model = "gpt-5.6-sol"
    max_rounds = 8

    description = (
        "Investigates whether a host is communicating maliciously — command-and-"
        "control beaconing, connections to known-bad IPs or domains, and repeated "
        "blocked web-filtering attempts. Use for 'is this host beaconing', 'is "
        "this host talking to C2', 'check network activity for host X', 'is this "
        "host exfiltrating or calling home'. Cross-checks destinations against the "
        "organization's Defender indicator list."
    )

    # KQL network events + the Defender indicator API, both via the registry.
    allowed_sources = ("network_events", "network_indicators")

    system_prompt = """You are a network-focused SOC analyst determining whether a
host is communicating maliciously.

Investigate:
1. host_connections — what the host talked to (destinations, ports, processes).
2. beaconing_pattern — regular repeated connections to one destination are the
   C2 calling-home signature; a high, steady per-hour rate to a single remote is
   strong evidence.
3. blocked_web_activity — repeated BLOCKED attempts to a destination mean an
   infected host retrying, not benign browsing.
4. check_indicator — for any suspicious destination the host contacted, check
   whether it is on the organization's Defender known-bad indicator list.

The decisive correlation: a host beaconing to an unusual destination AND
contacting an IP/domain that is on the indicator list is active command-and-
control. Either signal alone is weaker; together they are conclusive.

Conclude with a verdict:
- Cite evidence you retrieved; every key_evidence item carries a source and an
  identifier that resolves. For an indicator match, cite the destination value.
- A confirmed known-bad contact or clear beaconing warrants escalate.
- No suspicious connections found is NOT proof of safety if telemetry is thin —
  say so. Absence of evidence is not evidence of absence.
- Keep reasoning under 120 words.
"""

    tools = [
        Tool("host_connections", nt.host_connections, nt.CONNECTIONS_SCHEMA,
             required_sources=("network_events",)),
        Tool("beaconing_pattern", nt.beaconing_pattern, nt.BEACONING_SCHEMA,
             required_sources=("network_events",)),
        Tool("blocked_web_activity", nt.blocked_web_activity, nt.BLOCKED_SCHEMA,
             required_sources=("network_events",)),
        Tool("check_indicator", nt.check_indicator, nt.INDICATOR_SCHEMA,
             required_sources=("network_indicators",)),
    ]


if __name__ == "__main__":
    import json, sys
    agent = NetworkSpecialist()
    print("card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])
    if len(sys.argv) > 1:
        print(json.dumps(agent.run(" ".join(sys.argv[1:])).to_dict(), indent=2, default=str))
