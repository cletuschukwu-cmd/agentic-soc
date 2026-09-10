"""Network / C2 investigation tools.

Answers "is this host communicating maliciously" — beaconing, connections to
suspicious or known-bad destinations, blocked web-filtering hits, and cross-
checks against the organization's Defender indicator list.

Uses TWO transports transparently via the source registry:
  - network_events (KQL / DeviceNetworkEvents) for connection behaviour
  - network_indicators (rest_api / Defender API) for known-bad reputation
The tools call sources.query the same way for both; they never know the
transport differs.
"""

from typing import Any

import sources


def _kql(fragment: str, days: int = 7) -> dict[str, Any]:
    return sources.query("network_events", fragment, days=days)


def host_connections(host: str, days: int = 7) -> dict[str, Any]:
    """Outbound connections from a host: destinations, ports, initiating
    processes — the raw picture of what it talked to."""
    safe = host.replace("'", "")
    return _kql(
        f"{{table}} | where DeviceName startswith '{safe}' "
        f"| where isnotempty(RemoteIP) "
        f"| summarize Connections=count(), FirstSeen=min(TimeGenerated), "
        f"LastSeen=max(TimeGenerated), Ports=make_set(RemotePort,15), "
        f"Urls=make_set(RemoteUrl,15), "
        f"Processes=make_set(InitiatingProcessFileName,10) "
        f"by RemoteIP | order by Connections desc | take 30",
        days,
    )


def beaconing_pattern(host: str, days: int = 7) -> dict[str, Any]:
    """Regular, repeated connections to the same destination — the signature of
    malware calling home to C2 on a timer. Many connections to one remote over
    a sustained window is the tell."""
    safe = host.replace("'", "")
    return _kql(
        f"{{table}} | where DeviceName startswith '{safe}' and isnotempty(RemoteIP) "
        f"| summarize Hits=count(), "
        f"Span=datetime_diff('minute', max(TimeGenerated), min(TimeGenerated)), "
        f"DistinctUrls=dcount(RemoteUrl) "
        f"by RemoteIP, RemoteUrl "
        f"| where Hits >= 10 "
        f"| extend PerHour = round(Hits * 60.0 / (Span + 1), 1) "
        f"| order by Hits desc | take 20",
        days,
    )


def blocked_web_activity(host: str, days: int = 7) -> dict[str, Any]:
    """Web-filtering and connection blocks — attempts to reach destinations that
    were denied. Repeated blocked attempts to a suspicious destination indicate
    an infected host retrying, not benign browsing."""
    safe = host.replace("'", "")
    return _kql(
        f"{{table}} | where DeviceName startswith '{safe}' "
        f"| where ActionType has 'Block' or ActionType has 'Blocked' "
        f"| summarize Blocks=count(), Urls=make_set(RemoteUrl,15), "
        f"Actions=make_set(ActionType,10), "
        f"Processes=make_set(InitiatingProcessFileName,10) "
        f"by RemoteIP | order by Blocks desc | take 20",
        days,
    )


def check_indicator(value: str) -> dict[str, Any]:
    """Is an IP / domain / URL on the organization's Defender indicator list?
    Routed through the rest_api transport to the Defender API — the reputation
    cross-check that turns 'suspicious connection' into 'known-bad contact'."""
    return sources.query("network_indicators", value)


def _hschema(name, desc):
    return {
        "type": "function",
        "function": {
            "name": name, "description": desc,
            "parameters": {
                "type": "object", "additionalProperties": False, "required": ["host"],
                "properties": {
                    "host": {"type": "string", "description": "Hostname or device name."},
                    "days": {"type": "integer", "minimum": 1, "maximum": 30},
                },
            },
        },
    }


CONNECTIONS_SCHEMA = _hschema("host_connections",
    "Outbound connections from a host: destinations, ports, initiating processes.")
BEACONING_SCHEMA = _hschema("beaconing_pattern",
    "Regular repeated connections to the same destination — C2 beaconing signature.")
BLOCKED_SCHEMA = _hschema("blocked_web_activity",
    "Blocked web-filtering/connection attempts — an infected host retrying a denied destination.")
INDICATOR_SCHEMA = {
    "type": "function",
    "function": {
        "name": "check_indicator",
        "description": "Check whether an IP, domain, or URL is on the organization's Defender "
                       "known-bad indicator list. Use to confirm whether a destination a host "
                       "contacted is a known threat.",
        "parameters": {
            "type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {"value": {"type": "string", "description": "IP, domain, or URL."}},
        },
    },
}
