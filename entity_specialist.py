"""Entity investigation specialist.

The first real specialist on the agent base. Given an IP, hash, account, or
host, it investigates across the workspace and returns a grounded verdict.

Note the allowed_sources declaration: it is a fixed tuple written here, in
code, by the developer. The language model inside this agent cannot add to it
or reach past it. Those logical names resolve through the registry only to
tables a human has approved. Two stacked gates: the developer scopes the agent,
the human approves the tables.
"""

from agent_base import Specialist, Tool
import entity_tools as et


class EntitySpecialist(Specialist):
    name = "entity_investigator"
    description = (
        "Investigates a single indicator — an IP address, file hash, user "
        "account, or host — across network, endpoint, identity and threat-intel "
        "evidence. Use for questions like 'what do we know about 10.2.0.4', "
        "'is this hash malicious', 'has this account done anything unusual'."
    )

    # --- the declaration ---------------------------------------------------
    # Fixed in code. The AI cannot change this. It is this agent's blast radius.
    allowed_sources = (
        "network_events",
        "process_events",
        "file_events",
        "identity_info",
        "signins",
        "device_info",
        "alerts",
        "threat_intel",
    )

    max_rounds = 8

    system_prompt = """You are a senior SOC analyst investigating a single entity
— an IP, a file hash, an account, or a host — for another analyst.

Investigate like an experienced analyst under time pressure: form a hypothesis,
gather the MINIMUM evidence needed to confirm or deny it, then conclude. Do not
exhaustively enumerate every source. A good analyst knows when they have enough.

Work in gears, escalating only as needed:
1. FAST PATH. Call the one lookup tool matching the entity type. This curated
   summary is usually enough to conclude. If it answers the question, STOP and
   give your verdict — do not drill further.
2. INSPECT (only if you must drill). If the summary is genuinely too thin and
   you need raw events, call describe_source and sample_source on the ONE source
   you need, to learn its real schema. Do not inspect sources you will not query.
3. DEEP DIVE (only when warranted). Use deep_query on that source to fetch the
   specific raw events that would settle your hypothesis — not everything.

Budget discipline: you have limited time. Prefer concluding with good-enough
evidence over gathering perfect evidence. Chase a secondary indicator (a found
hash or IP) only if it is central to the verdict, not reflexively.

Conclude with a verdict:
- Cite evidence you actually retrieved; every key_evidence item carries a source
  table and an identifier that resolves in it. Never invent identifiers.
- Calibrate confidence honestly; reserve above 0.85 for unambiguous evidence.
- Weight errors asymmetrically: missing a real threat is worse than a false
  alarm. When torn, prefer investigate.
- Keep reasoning under 120 words.
"""

    tools = [
        Tool("lookup_ip", et.lookup_ip, et.IP_SCHEMA,
             required_sources=("network_events", "threat_intel")),
        Tool("lookup_hash", et.lookup_hash, et.HASH_SCHEMA,
             required_sources=("process_events", "file_events", "threat_intel")),
        Tool("lookup_account", et.lookup_account, et.ACCOUNT_SCHEMA,
             required_sources=("identity_info", "signins")),
        Tool("lookup_host", et.lookup_host, et.HOST_SCHEMA,
             required_sources=("device_info", "alerts", "process_events")),
        Tool("describe_source", et.describe_source, et.DESCRIBE_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
        Tool("sample_source", et.sample_source, et.SAMPLE_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
        Tool("deep_query", et.deep_query, et.DEEP_QUERY_SCHEMA,
             required_sources=("process_events", "network_events", "file_events", "alerts")),
    ]


if __name__ == "__main__":
    import json
    import sys

    agent = EntitySpecialist()
    print("agent card:", json.dumps(agent.card(), indent=2))
    print("\nauthorized tools for this customer:",
          [t.name for t in agent._authorized_tools()])

    if len(sys.argv) > 1:
        task = " ".join(sys.argv[1:])
        print(f"\ninvestigating: {task}\n")
        result = agent.run(task)
        print(json.dumps(result.to_dict(), indent=2, default=str))
