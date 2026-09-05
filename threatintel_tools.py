"""Threat-intelligence enrichment tools.

Checks an indicator (IP, domain, URL, file hash) against known-bad intelligence.
Today this queries the customer's ingested ThreatIntelIndicators table (STIX
format). External feeds (Google TI, VirusTotal, MISP) slot in later through the
source registry's rest_api / ingested modes — marked below.

Critical discipline (Risk R4): "no intel match" is NOT "benign". A novel or
targeted indicator no feed has seen yet returns nothing here. The tools report
absence honestly; they never imply safety from absence.
"""

from typing import Any

import sources


def _q(fragment: str, days: int = 90) -> dict[str, Any]:
    # TI is reference data, not time-series events — look back far by default.
    return sources.query("threat_intel", fragment, days=days)


def lookup_indicator(value: str, days: int = 90) -> dict[str, Any]:
    """Is this exact indicator (IP, hash, domain, URL) known bad? Returns active,
    non-revoked matches with confidence, pattern, tags and validity."""
    safe = value.replace("'", "")
    result = _q(
        f"{{table}} | where ObservableValue =~ '{safe}' "
        f"| where IsActive == true and Revoked == false "
        f"| project ObservableKey, ObservableValue, Pattern, Confidence, Tags, "
        f"ValidFrom, ValidUntil, Type "
        f"| order by Confidence desc | take 10",
        days,
    )
    result["indicator"] = value
    result["interpretation"] = (
        "match_found" if result.get("row_count") else "no_intel_match_not_a_safety_signal"
    )
    return result


def lookup_indicators_bulk(values: list[str], days: int = 90) -> dict[str, Any]:
    """Check several indicators from one incident at once. Correlated hits
    (multiple indicators from the same incident all known-bad) are a strong
    coordinated-attack signal."""
    if not values:
        return {"available": False, "reason": "no indicators provided", "rows": []}
    quoted = ",".join(f"'{v.replace(chr(39), '')}'" for v in values[:25])
    result = _q(
        f"{{table}} | where ObservableValue in~ ({quoted}) "
        f"| where IsActive == true and Revoked == false "
        f"| project ObservableValue, ObservableKey, Pattern, Confidence, Tags, ValidUntil "
        f"| order by Confidence desc | take 50",
        days,
    )
    matched = {r.get("ObservableValue") for r in result.get("rows", [])}
    result["checked"] = values
    result["matched_count"] = len(matched)
    result["unmatched"] = [v for v in values if v not in matched]
    return result


def search_by_tag(tag: str, days: int = 90) -> dict[str, Any]:
    """Find indicators associated with a campaign, malware family, or actor tag —
    e.g. 'is anything from campaign X in our intel'."""
    safe = tag.replace("'", "")
    return _q(
        f"{{table}} | where Tags has '{safe}' and IsActive == true and Revoked == false "
        f"| project ObservableValue, ObservableKey, Confidence, Tags, ValidUntil "
        f"| order by Confidence desc | take 30",
        days,
    )


# --- external feeds: future slots (not implemented) -------------------------
# When a customer has Google TI / VirusTotal / MISP wired via the source
# registry (rest_api live in commercial, ingested in Gov), add tools here that
# call sources.query("google_ti", ...) etc. The specialist already reasons over
# whatever intel sources return; only the tool/source wiring is new.


# --- schemas ----------------------------------------------------------------

INDICATOR_SCHEMA = {
    "type": "function",
    "function": {
        "name": "lookup_indicator",
        "description": "Check one indicator (IP, file hash, domain, or URL) against known-bad "
                       "threat intelligence. Returns matches with confidence, or none. "
                       "No match does NOT mean safe.",
        "parameters": {
            "type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {
                "value": {"type": "string", "description": "The IP, hash, domain, or URL."},
                "days": {"type": "integer", "minimum": 1, "maximum": 365},
            },
        },
    },
}

BULK_SCHEMA = {
    "type": "function",
    "function": {
        "name": "lookup_indicators_bulk",
        "description": "Check several indicators from one incident at once. Multiple known-bad "
                       "matches from the same incident indicate a coordinated attack.",
        "parameters": {
            "type": "object", "additionalProperties": False, "required": ["values"],
            "properties": {
                "values": {"type": "array", "items": {"type": "string"},
                           "description": "Indicators (IPs, hashes, domains, URLs)."},
                "days": {"type": "integer", "minimum": 1, "maximum": 365},
            },
        },
    },
}

TAG_SCHEMA = {
    "type": "function",
    "function": {
        "name": "search_by_tag",
        "description": "Find intel indicators associated with a campaign, malware family, or "
                       "threat-actor tag.",
        "parameters": {
            "type": "object", "additionalProperties": False, "required": ["tag"],
            "properties": {
                "tag": {"type": "string", "description": "Campaign, family, or actor name."},
                "days": {"type": "integer", "minimum": 1, "maximum": 365},
            },
        },
    },
}
