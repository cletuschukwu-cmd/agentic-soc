"""Agent tools.

Implemented as plain functions with explicit JSON schemas, bound through
function calling. Deliberately NOT MCP and NOT the OpenAPI tool: both are
unavailable in Azure Government, so building on them would produce a system
that cannot be lifted into a Gov tenant. Each function here maps 1:1 to an
Azure Function when you deploy it.

Every tool fails soft. If a table is missing (UEBA not enabled, Defender XDR
connector absent) the tool returns an availability note rather than raising,
so the model reports insufficient_evidence instead of the run crashing.
"""

import re
from typing import Any

import config
import schema
from envelope import run_kql

_TABLE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")
_FORBIDDEN = re.compile(
    r"\b(externaldata|http|evaluate\s+bag_unpack|\.create|\.drop|\.set|\.append|\.ingest)\b",
    re.IGNORECASE,
)


def _guard(query: str) -> str | None:
    """Return a rejection reason, or None if the query is acceptable.

    Tables must be human-approved for this customer (discover-then-approve).
    The agent can never query a table a person has not blessed, which is what
    keeps the free-KQL path from becoming a way to reach anywhere in the
    workspace.
    """
    if _FORBIDDEN.search(query):
        return "query contains a forbidden operator"
    match = _TABLE_RE.match(query)
    if not match:
        return "could not identify the source table"
    table = match.group(1)
    if not schema.is_approved(table):
        return (f"table '{table}' is not approved for agent query in this "
                f"customer environment")
    return None


def _safe(rows_fn) -> dict[str, Any]:
    try:
        rows = rows_fn()
        return {"available": True, "row_count": len(rows), "rows": rows}
    except Exception as exc:  # noqa: BLE001 - fail soft by design
        return {"available": False, "reason": str(exc)[:200], "rows": []}


# --- Implementations --------------------------------------------------------


def run_scoped_kql(query: str, days: int = 7) -> dict[str, Any]:
    reason = _guard(query)
    if reason:
        return {"available": False, "reason": reason, "rows": []}
    capped = f"{query}\n| take {config.MAX_ROWS}"
    return _safe(lambda: run_kql(capped, days=days))


IDENTITY_QUERY = """
IdentityInfo
| where AccountUPN =~ '{upn}' or AccountName =~ '{upn}'
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| project AccountUPN, AccountObjectId, AccountName, IsAccountEnabled, UserType,
          AssignedRoles, GroupMembership, JobTitle, Department, Manager,
          RiskLevel, RiskState, BlastRadius
"""

SIGNIN_QUERY = """
SigninLogs
| where UserPrincipalName =~ '{upn}'
| summarize Attempts = count(),
            Failures = countif(ResultType != 0),
            Countries = make_set(LocationDetails.countryOrRegion, 10),
            Apps = make_set(AppDisplayName, 10),
            RiskyCount = countif(RiskLevelDuringSignIn in ('medium','high'))
  by UserPrincipalName
"""


def get_identity_context(upn: str, days: int = 7) -> dict[str, Any]:
    safe = upn.replace("'", "")
    identity = _safe(lambda: run_kql(IDENTITY_QUERY.format(upn=safe), days=days))
    signins = _safe(lambda: run_kql(SIGNIN_QUERY.format(upn=safe), days=days))
    return {
        "upn": upn,
        "identity": identity,
        "signin_summary": signins,
        "note": (
            "IdentityInfo requires UEBA to be enabled. If unavailable, the "
            "signin summary is the only identity signal."
        ),
    }


DEVICE_QUERY = """
DeviceInfo
| where DeviceName =~ '{name}' or DeviceId =~ '{name}'
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion, PublicIP, IsAzureADJoined,
          JoinType, DeviceType, OnboardingStatus, MachineGroup, LoggedOnUsers
"""


def get_device_context(device: str, days: int = 7) -> dict[str, Any]:
    safe = device.replace("'", "")
    return {
        "device": device,
        "info": _safe(lambda: run_kql(DEVICE_QUERY.format(name=safe), days=days)),
        "note": "DeviceInfo requires the Defender XDR connector.",
    }


RULE_HISTORY_QUERY = """
SecurityIncident
| where Title =~ '{title}' and Status == 'Closed' and isnotempty(Classification)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize Total = count(),
            TruePositive = countif(Classification == 'TruePositive'),
            BenignPositive = countif(Classification == 'BenignPositive'),
            FalsePositive = countif(Classification == 'FalsePositive'),
            MedianDwellMin = percentile(datetime_diff('minute', ClosedTime, CreatedTime), 50)
"""


def get_rule_history(title: str, days: int = 14) -> dict[str, Any]:
    """How this detection has historically been dispositioned by analysts.

    Institutional memory: the thing a senior analyst supplies from experience
    and that no off-the-shelf product knows about your environment.
    """
    safe = title.replace("'", "")
    return {
        "title": title,
        "history": _safe(lambda: run_kql(RULE_HISTORY_QUERY.format(title=safe), days=days)),
    }


# --- Schemas ----------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "run_scoped_kql",
            "description": (
                "Run a read-only KQL query against the customer's Sentinel "
                "workspace. Only human-approved tables may be queried; a query "
                "against an unapproved table is rejected. Results are capped at "
                f"{config.MAX_ROWS} rows."
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "KQL starting with a table name."},
                    "days": {"type": "integer", "minimum": 1, "maximum": config.MAX_TIMESPAN_DAYS},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_identity_context",
            "description": "Privilege, risk state and sign-in summary for an account.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["upn"],
                "properties": {
                    "upn": {"type": "string"},
                    "days": {"type": "integer", "minimum": 1, "maximum": config.MAX_TIMESPAN_DAYS},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_device_context",
            "description": "Platform, join state and onboarding status for a device.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["device"],
                "properties": {
                    "device": {"type": "string"},
                    "days": {"type": "integer", "minimum": 1, "maximum": config.MAX_TIMESPAN_DAYS},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_rule_history",
            "description": (
                "How analysts have historically closed incidents from this same "
                "detection. Use this before concluding; a rule that is 95 percent "
                "false positive is strong prior evidence."
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["title"],
                "properties": {
                    "title": {"type": "string", "description": "Exact incident Title."},
                    "days": {"type": "integer", "minimum": 1, "maximum": config.MAX_TIMESPAN_DAYS},
                },
            },
        },
    },
]

DISPATCH = {
    "run_scoped_kql": run_scoped_kql,
    "get_identity_context": get_identity_context,
    "get_device_context": get_device_context,
    "get_rule_history": get_rule_history,
}
