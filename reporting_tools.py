"""Summarization / reporting tools.

Aggregate views over incidents and alerts for reports — not single-entity
lookups. Feeds shift handovers, weekly summaries, and exec briefs. Read-only,
aggregate, over the incidents and alerts sources.
"""

from typing import Any

import sources


def _q(logical: str, fragment: str, days: int) -> dict[str, Any]:
    return sources.query(logical, fragment, days=days)


def incident_overview(days: int = 7) -> dict[str, Any]:
    """Counts by severity, status, and classification over the window."""
    return _q(
        "incidents",
        f"{{table}} | summarize arg_max(TimeGenerated, *) by IncidentNumber "
        f"| summarize Total=count(), "
        f"New=countif(Status=='New'), Active=countif(Status=='Active'), "
        f"Closed=countif(Status=='Closed'), "
        f"High=countif(Severity=='High'), Medium=countif(Severity=='Medium'), "
        f"Low=countif(Severity=='Low'), "
        f"TruePositive=countif(Classification=='TruePositive'), "
        f"FalsePositive=countif(Classification=='FalsePositive'), "
        f"BenignPositive=countif(Classification=='BenignPositive'), "
        f"Undetermined=countif(Classification=='Undetermined')",
        days,
    )


def top_incident_types(days: int = 7) -> dict[str, Any]:
    """Most frequent incident titles — what's driving volume."""
    return _q(
        "incidents",
        f"{{table}} | summarize arg_max(TimeGenerated, *) by IncidentNumber "
        f"| summarize Count=count(), "
        f"High=countif(Severity=='High'), "
        f"Open=countif(Status!='Closed') by Title "
        f"| order by Count desc | take 15",
        days,
    )


def notable_incidents(days: int = 7) -> dict[str, Any]:
    """Individual high-severity or still-open incidents worth attention, with
    resolvable IDs for citation."""
    return _q(
        "incidents",
        f"{{table}} | summarize arg_max(TimeGenerated, *) by IncidentNumber "
        f"| where Severity in ('High','Medium') or Status != 'Closed' "
        f"| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime "
        f"| order by CreatedTime desc | take 20",
        days,
    )


def alert_trends(days: int = 7) -> dict[str, Any]:
    """Top alert names by volume and product — the detection-level picture."""
    return _q(
        "alerts",
        f"{{table}} | summarize Count=count(), "
        f"Products=make_set(ProductName, 5), "
        f"Severities=make_set(AlertSeverity, 5) by AlertName "
        f"| order by Count desc | take 20",
        days,
    )


def _schema(name, desc):
    return {
        "type": "function",
        "function": {
            "name": name, "description": desc,
            "parameters": {
                "type": "object", "additionalProperties": False, "required": [],
                "properties": {"days": {"type": "integer", "minimum": 1, "maximum": 90}},
            },
        },
    }


OVERVIEW_SCHEMA = _schema("incident_overview",
    "Counts of incidents by severity, status, and classification over the window.")
TYPES_SCHEMA = _schema("top_incident_types",
    "The most frequent incident types (titles) driving volume.")
NOTABLE_SCHEMA = _schema("notable_incidents",
    "Individual high-severity or still-open incidents worth attention, with IDs.")
TRENDS_SCHEMA = _schema("alert_trends",
    "Top alert names by volume and product — the detection-level picture.")
