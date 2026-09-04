"""The verdict contract.

Two design choices carry most of the weight here:

1. `insufficient_evidence` is a first-class verdict. A model that can say
   "I cannot tell, and here is what is missing" earns trust that one which
   always produces an answer never will. The rate at which it fires also
   tells you where your enrichment is thin.

2. Every claim carries a source table and an identifier, so groundedness is
   machine-checkable. verify_citations() resolves each identifier against the
   workspace. A verdict with unresolvable citations is flagged before an
   analyst ever sees it. This is the property that makes the system
   defensible in an audit, and it is the one thing an off-the-shelf product
   cannot give a mission owner.
"""

from typing import Any

VERDICT_VALUES = [
    "likely_true_positive",
    "likely_benign",
    "likely_false_positive",
    "insufficient_evidence",
]

CITABLE_SOURCES = [
    "SecurityIncident",
    "SecurityAlert",
    "IdentityInfo",
    "DeviceInfo",
    "SigninLogs",
    "AuditLogs",
]

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "confidence",
        "reasoning",
        "key_evidence",
        "escalation_factors",
        "recommended_action",
        "unavailable_context",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": VERDICT_VALUES},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reasoning": {
            "type": "string",
            "description": "Under 120 words. State what drove the verdict, not a recap of the alert.",
        },
        "key_evidence": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["claim", "source", "identifier"],
                "properties": {
                    "claim": {"type": "string"},
                    "source": {"type": "string", "enum": CITABLE_SOURCES},
                    "identifier": {
                        "type": "string",
                        "description": "A value that resolves in the source table: SystemAlertId, AccountObjectId, DeviceId, IncidentNumber.",
                    },
                },
            },
        },
        "escalation_factors": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string"},
        },
        "recommended_action": {
            "type": "string",
            "enum": ["close", "investigate", "escalate"],
        },
        "unavailable_context": {
            "type": "array",
            "maxItems": 6,
            "items": {"type": "string"},
            "description": "Context that would have changed the verdict but could not be retrieved.",
        },
    },
}

RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {"name": "triage_verdict", "strict": True, "schema": VERDICT_SCHEMA},
}

# Maps an identifier to the column it should resolve against.
_RESOLVERS = {
    "SecurityAlert": "SystemAlertId",
    "SecurityIncident": "IncidentNumber",
    "IdentityInfo": "AccountObjectId",
    "DeviceInfo": "DeviceId",
    "SigninLogs": "Id",
    "AuditLogs": "CorrelationId",
}


def verify_citations(verdict: dict, run_kql) -> dict:
    """Resolve every cited identifier. Returns a groundedness report.

    run_kql is any callable taking (query, days) and returning a list of rows,
    so this works against the live workspace or a recorded fixture.
    """
    checks, resolved = [], 0
    for item in verdict.get("key_evidence", []):
        table, ident = item["source"], item["identifier"]
        column = _RESOLVERS.get(table)
        ok = False
        if column:
            safe = ident.replace("'", "")
            try:
                rows = run_kql(
                    f"{table} | where tostring({column}) == '{safe}' | take 1", days=14
                )
                ok = len(rows) > 0
            except Exception:
                ok = False
        checks.append({"source": table, "identifier": ident, "resolved": ok})
        resolved += int(ok)

    total = len(checks) or 1
    return {
        "citations_total": len(checks),
        "citations_resolved": resolved,
        "groundedness": round(resolved / total, 3),
        "flagged": resolved < len(checks),
        "checks": checks,
    }


# Analyst closure classification -> expected verdict, for backtesting.
LABEL_MAP = {
    "TruePositive": "likely_true_positive",
    "BenignPositive": "likely_benign",
    "FalsePositive": "likely_false_positive",
}
