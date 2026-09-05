"""Correlation specialist — the first consultation-based agent.

Instead of re-implementing identity, entity, and threat-intel logic, this
specialist CONSULTS the other specialists and correlates their findings into a
single attack-chain narrative. It reasons across domains — identity + endpoint +
network + intel — to answer "are these events one coordinated attack, and what
is the chain."

Why consultation, not a wide scope of its own: each consulted specialist runs
under ITS OWN least-privilege scope and returns only its verdict. The correlator
never inherits their data access. This is how least-privilege survives
composition — the whole point of the multi-agent design.

Version A (now): correlates across the customer's own data domains via the
existing specialists. Version B (later): the same agent gains cross-SIEM reach
automatically when Splunk/ArcSight specialists are registered — it just has more
specialists to consult.
"""

from agent_base import Specialist, Tool


# --- consultation tools -----------------------------------------------------
# These call orchestrator.consult lazily (imported inside the function) to avoid
# a circular import, since the orchestrator registers this specialist.

def consult_entity(query: str) -> dict:
    """Ask the entity investigator about an IP, hash, account, or host."""
    from orchestrator import consult
    return _slim(consult("entity_investigator", query))


def consult_identity(query: str) -> dict:
    """Ask the identity investigator whether an account is compromised."""
    from orchestrator import consult
    return _slim(consult("identity_investigator", query))


def consult_threat_intel(query: str) -> dict:
    """Ask the threat-intel specialist whether indicators are known bad."""
    from orchestrator import consult
    return _slim(consult("threat_intel", query))


def consult_triage(query: str) -> dict:
    """Ask the triage specialist to assess a specific incident by number."""
    from orchestrator import consult
    return _slim(consult("incident_triage", query))


def _slim(result: dict) -> dict:
    """Return just what the correlator needs from a consulted specialist: its
    verdict, confidence, reasoning, key evidence, and which agent produced it —
    not the full tool trace. Keeps the correlator's context focused."""
    if result.get("status") != "ok" or not result.get("verdict"):
        return {"agent": result.get("agent"), "status": result.get("status"),
                "reason": result.get("reason", "no verdict")}
    v = result["verdict"]
    return {
        "agent": result.get("agent"),
        "verdict": v.get("verdict"),
        "confidence": v.get("confidence"),
        "reasoning": v.get("reasoning"),
        "key_evidence": v.get("key_evidence", []),
        "escalation_factors": v.get("escalation_factors", []),
    }


def _cschema(name, desc):
    return {
        "type": "function",
        "function": {
            "name": name, "description": desc,
            "parameters": {
                "type": "object", "additionalProperties": False, "required": ["query"],
                "properties": {"query": {"type": "string",
                    "description": "The specific question to ask that specialist."}},
            },
        },
    }


class CorrelationSpecialist(Specialist):
    name = "correlation_investigator"
    model = "gpt-5.6-sol"
    max_rounds = 8

    description = (
        "Correlates evidence across identity, endpoint, network, and threat "
        "intelligence to determine whether separate events are one coordinated "
        "attack, and to reconstruct the attack chain. Use for broad questions "
        "like 'is this a coordinated attack', 'connect the activity on this host "
        "and this account', 'walk me through what happened end to end', "
        "'reconstruct the attack involving X'. It consults the other specialists "
        "and composes their findings — it does not query raw data directly."
    )

    # Deliberately minimal direct scope. Its power comes from consulting other
    # specialists, each of which holds its own scope. The correlator itself
    # touches no data source directly.
    allowed_sources = ()

    system_prompt = """You are a lead SOC analyst correlating a multi-part
situation into a single coherent picture.

You do not query raw data yourself. You direct specialists and synthesise their
findings:
- consult_entity — for a host, IP, hash, or account (endpoint/network view)
- consult_identity — for whether an account is compromised (sign-in view)
- consult_threat_intel — for whether indicators are known bad
- consult_triage — to assess a specific incident by number

Method:
1. Break the situation into the entities and questions it contains.
2. Consult the right specialist for each — an account goes to identity, an
   indicator to threat-intel, a host/IP/hash to entity, an incident to triage.
3. Correlate: do the findings connect into one attack chain? Look for a sequence
   — e.g. account compromise, then execution on a host, then a connection to a
   known-bad IP. Coincidence in time, shared entities, and corroborating intel
   are what turn separate alerts into one attack.
4. Consult more only if a gap in the chain matters. Do not consult reflexively.

Conclude with a verdict on the SITUATION AS A WHOLE:
- Cite the specialists' findings and their evidence identifiers. Attribute which
  specialist established each point.
- If the pieces connect into a coordinated attack, say so and lay out the chain
  in order. If they are unrelated, say that too.
- insufficient_evidence if the specialists could not establish enough.
- Missing a real coordinated attack is far worse than over-connecting. When the
  chain is plausible, escalate.
- Keep reasoning under 150 words (a chain needs a little more room).
"""

    tools = [
        Tool("consult_entity", consult_entity, _cschema("consult_entity",
             "Consult the entity investigator about a host, IP, file hash, or account.")),
        Tool("consult_identity", consult_identity, _cschema("consult_identity",
             "Consult the identity investigator about whether an account is compromised.")),
        Tool("consult_threat_intel", consult_threat_intel, _cschema("consult_threat_intel",
             "Consult the threat-intel specialist about whether indicators are known bad.")),
        Tool("consult_triage", consult_triage, _cschema("consult_triage",
             "Consult the triage specialist to assess a specific incident by number.")),
    ]


if __name__ == "__main__":
    import json, sys
    agent = CorrelationSpecialist()
    print("card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])
    if len(sys.argv) > 1:
        print(json.dumps(agent.run(" ".join(sys.argv[1:])).to_dict(), indent=2, default=str))
