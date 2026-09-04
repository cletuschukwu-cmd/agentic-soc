"""Entity investigation tools.

Look up what the workspace knows about a single entity — an IP address, a file
hash, an account, or a host. Each tool asks the source registry for a logical
capability and never names a raw table, so the same tool works across customers
with different schemas.

Every tool fails soft: an unavailable source returns an availability note, not
an exception, so the agent reports insufficient_evidence rather than crashing.
"""

from typing import Any

import sources


def _q(logical: str, fragment: str, days: int) -> dict[str, Any]:
    """Query a logical source; uniform shape back regardless of transport."""
    return sources.query(logical, fragment, days=days)


# --- IP address -------------------------------------------------------------

def lookup_ip(ip: str, days: int = 7) -> dict[str, Any]:
    """Where an IP appeared: network connections, and any threat-intel match."""
    safe = ip.replace("'", "")
    net = _q(
        "network_events",
        f"{{table}} | where RemoteIP == '{safe}' or LocalIP == '{safe}' "
        f"| summarize Connections=count(), Devices=make_set(DeviceName, 10), "
        f"Ports=make_set(RemotePort, 15), Actions=make_set(ActionType, 10) ",
        days,
    )
    ti = _q(
        "threat_intel",
        f"{{table}} | where NetworkIP == '{safe}' or NetworkSourceIP == '{safe}' "
        f"| project ThreatType, Description, ConfidenceScore, SourceSystem, Active "
        f"| take 5",
        days,
    )
    return {"entity": ip, "entity_type": "ip", "network": net, "threat_intel": ti}


# --- File hash --------------------------------------------------------------

def lookup_hash(file_hash: str, days: int = 7) -> dict[str, Any]:
    """Where a hash was seen executing or written, and any TI match."""
    safe = file_hash.replace("'", "")
    proc = _q(
        "process_events",
        f"{{table}} | where SHA256 == '{safe}' or SHA1 == '{safe}' or MD5 == '{safe}' "
        f"| summarize Executions=count(), Devices=make_set(DeviceName, 10), "
        f"Files=make_set(FileName, 10), Cmds=make_set(ProcessCommandLine, 5) ",
        days,
    )
    files = _q(
        "file_events",
        f"{{table}} | where SHA256 == '{safe}' or SHA1 == '{safe}' "
        f"| summarize Seen=count(), Devices=make_set(DeviceName, 10), "
        f"Names=make_set(FileName, 10), Paths=make_set(FolderPath, 10) ",
        days,
    )
    ti = _q(
        "threat_intel",
        f"{{table}} | where FileHashValue == '{safe}' "
        f"| project ThreatType, Description, ConfidenceScore, Active | take 5",
        days,
    )
    return {"entity": file_hash, "entity_type": "hash",
            "process": proc, "file": files, "threat_intel": ti}


# --- Account ----------------------------------------------------------------

def lookup_account(account: str, days: int = 7) -> dict[str, Any]:
    """Identity profile plus sign-in behaviour for an account."""
    safe = account.replace("'", "")
    identity = _q(
        "identity_info",
        f"{{table}} | where AccountUPN =~ '{safe}' or AccountName =~ '{safe}' "
        f"| summarize arg_max(TimeGenerated, *) by AccountObjectId "
        f"| project AccountUPN, AccountObjectId, AccountName, IsAccountEnabled, "
        f"UserType, AssignedRoles, GroupMembership, JobTitle, Department, RiskLevel, BlastRadius",
        days,
    )
    signins = _q(
        "signins",
        f"{{table}} | where UserPrincipalName =~ '{safe}' "
        f"| summarize Attempts=count(), Failures=countif(ResultType != 0), "
        f"Countries=make_set(tostring(LocationDetails.countryOrRegion), 10), "
        f"Apps=make_set(AppDisplayName, 10), "
        f"Risky=countif(RiskLevelDuringSignIn in ('medium','high')) ",
        days,
    )
    return {"entity": account, "entity_type": "account",
            "identity": identity, "signins": signins}


# --- Host -------------------------------------------------------------------

def lookup_host(host: str, days: int = 7) -> dict[str, Any]:
    """Device profile, individual recent alerts, and recent process activity."""
    safe = host.replace("'", "")
    info = _q(
        "device_info",
        f"{{table}} | where DeviceName =~ '{safe}' or DeviceId =~ '{safe}' "
        f"| summarize arg_max(TimeGenerated, *) by DeviceId "
        f"| project DeviceId, DeviceName, OSPlatform, OSVersion, PublicIP, "
        f"IsAzureADJoined, JoinType, OnboardingStatus, MachineGroup, LoggedOnUsers",
        days,
    )
    # Individual alert records with resolvable IDs, not just a count, so the
    # agent can cite specific alerts and reason on tactics/severity.
    alerts = _q(
        "alerts",
        f"{{table}} | where Entities has '{safe}' "
        f"| summarize arg_max(TimeGenerated, *) by SystemAlertId "
        f"| project SystemAlertId, AlertName, AlertSeverity, Tactics, "
        f"ProductName, StartTime "
        f"| order by StartTime desc | take 15",
        days,
    )
    # Recent process activity gives the agent real endpoint behaviour to judge.
    procs = _q(
        "process_events",
        f"{{table}} | where DeviceName =~ '{safe}' "
        f"| summarize Runs=count() by FileName, FolderPath "
        f"| order by Runs desc | take 15",
        days,
    )
    return {"entity": host, "entity_type": "host",
            "device": info, "recent_alerts": alerts, "recent_processes": procs}


def deep_query(logical_source: str, kql_fragment: str, days: int = 7) -> dict[str, Any]:
    """Drill into raw events when curated lookups are too thin.

    logical_source is one of the agent's approved sources (e.g. 'process_events',
    'network_events'). kql_fragment is a KQL fragment that uses {table} as a
    placeholder — the registry substitutes the customer's real table. This lets
    the agent fetch actual event records and analyse them itself, but only
    within its approved sources: 'go look at the raw data' can never mean 'look
    at anything'.
    """
    frag = kql_fragment.strip()
    if "{table}" not in frag:
        # Force the placeholder so the agent cannot name a table directly and
        # bypass the registry's approval-gated resolution.
        return {"available": False,
                "reason": "kql_fragment must reference {table}, not a table name directly",
                "rows": []}
    forbidden = ("externaldata", "http://", "https://", ".create", ".drop",
                 ".set", ".append", ".ingest")
    if any(f in frag.lower() for f in forbidden):
        return {"available": False, "reason": "fragment contains a forbidden operator", "rows": []}
    # Cap rows so a drill-down cannot scan-and-dump a whole table.
    if "take " not in frag.lower() and "limit " not in frag.lower():
        frag = f"{frag}\n| take 50"
    return _q(logical_source, frag, days)


def describe_source(logical_source: str) -> dict[str, Any]:
    """Return the real column names of an approved source.

    Lets the agent read a table's actual schema before drilling, so its
    deep_query fragments match the customer's real fields instead of guessing.
    This is what makes deep analysis portable: the agent adapts to whatever
    schema a customer has rather than assuming column names.
    """
    # getschema is cheap and returns the column/type list without scanning data.
    result = _q(logical_source, "{table} | getschema | project ColumnName, ColumnType", days=1)
    if not result.get("available"):
        return result
    cols = [{"name": r.get("ColumnName"), "type": r.get("ColumnType")}
            for r in result.get("rows", [])]
    return {"available": True, "source": logical_source,
            "column_count": len(cols), "columns": cols}


def sample_source(logical_source: str, days: int = 7) -> dict[str, Any]:
    """Return a few recent rows from an approved source, to show real value
    shapes (e.g. whether DeviceName holds 'host' or 'host.fqdn.net'). Helps the
    agent write correct filters before a full drill-down."""
    return _q(logical_source, "{table} | take 3", days)


DESCRIBE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "describe_source",
        "description": (
            "Return the real column names and types of an approved source. Call "
            "this BEFORE deep_query on a table you are unsure about, so your KQL "
            "matches the customer's actual schema instead of guessing column names."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["logical_source"],
            "properties": {
                "logical_source": {"type": "string",
                                   "description": "An approved logical source, e.g. process_events."},
            },
        },
    },
}

SAMPLE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "sample_source",
        "description": (
            "Return a few recent rows from an approved source to see the real "
            "shape of values (e.g. whether a host field holds a short name or an "
            "FQDN). Use to get filters right before a full deep_query."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["logical_source"],
            "properties": {
                "logical_source": {"type": "string", "description": "An approved logical source."},
                "days": {"type": "integer", "minimum": 1, "maximum": 30},
            },
        },
    },
}


DEEP_QUERY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "deep_query",
        "description": (
            "Drill into raw event records when the curated lookups are too thin "
            "to conclude. Use this AFTER a lookup returns insufficient detail — "
            "to fetch actual process, network, or file events and analyse them "
            "yourself. logical_source must be one of your approved sources. Write "
            "the KQL fragment using {table} as a placeholder for the real table; "
            "results are capped."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["logical_source", "kql_fragment"],
            "properties": {
                "logical_source": {
                    "type": "string",
                    "description": "An approved logical source, e.g. process_events, network_events, file_events, alerts.",
                },
                "kql_fragment": {
                    "type": "string",
                    "description": "KQL using {table} as the table placeholder, e.g. \"{table} | where DeviceName =~ 'x' | project ...\".",
                },
                "days": {"type": "integer", "minimum": 1, "maximum": 30},
            },
        },
    },
}


# --- Schemas (function-calling contracts) -----------------------------------

def _schema(name: str, desc: str, arg: str, arg_desc: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": [arg],
                "properties": {
                    arg: {"type": "string", "description": arg_desc},
                    "days": {"type": "integer", "minimum": 1, "maximum": 30},
                },
            },
        },
    }


IP_SCHEMA = _schema("lookup_ip",
                    "Look up an IP address: network connections and threat-intel matches.",
                    "ip", "The IP address to investigate.")
HASH_SCHEMA = _schema("lookup_hash",
                      "Look up a file hash (SHA256/SHA1/MD5): where it executed or was written, plus threat intel.",
                      "file_hash", "The file hash to investigate.")
ACCOUNT_SCHEMA = _schema("lookup_account",
                         "Look up an account: identity profile, privileges, risk, and sign-in behaviour.",
                         "account", "The UPN or account name to investigate.")
HOST_SCHEMA = _schema("lookup_host",
                      "Look up a host: device profile and recent alert activity.",
                      "host", "The hostname or device id to investigate.")
