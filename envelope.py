"""Evidence envelope.

This is the piece that actually costs you time, and everything else is a
different prompt over the same object. Get this right and triage, shift
handoff, and timeline generation all become cheap.

The Entities field on SecurityAlert is nested JSON with inconsistent shapes
across detection products. parse_entities() handles the common types and
ignores the rest rather than failing.
"""

import json
from datetime import timedelta
from typing import Any

from azure.monitor.query import LogsQueryClient, LogsQueryStatus

import config

_client: LogsQueryClient | None = None


def logs_client() -> LogsQueryClient:
    global _client
    if _client is None:
        _client = LogsQueryClient(
            config.credential(), endpoint=config.profile().logs_endpoint
        )
    return _client


def run_kql(query: str, days: int = 7) -> list[dict[str, Any]]:
    """Execute a KQL query and return rows as dicts."""
    days = min(days, config.MAX_QUERY_TIMESPAN_DAYS)
    workspace = config.require("AISOC_WORKSPACE_ID", config.WORKSPACE_ID)
    resp = logs_client().query_workspace(
        workspace_id=workspace,
        query=query,
        timespan=timedelta(days=days),
        server_timeout=config.TOOL_TIMEOUT_SECONDS,
    )
    if resp.status == LogsQueryStatus.FAILURE:
        raise RuntimeError(str(resp.partial_error or "query failed"))
    tables = resp.tables if resp.status == LogsQueryStatus.SUCCESS else resp.partial_data
    rows: list[dict[str, Any]] = []
    for table in tables:
        for row in table.rows:
            rows.append(dict(zip(table.columns, row)))
    return rows[: config.MAX_ROWS]


_ENTITY_FIELDS = {
    "account": ["Name", "UPNSuffix", "AadUserId", "NTDomain", "Sid", "DisplayName", "IsDomainJoined"],
    "host": ["HostName", "FQDN", "DnsDomain", "NetBiosName", "OSFamily", "OSVersion",
             "MdatpDeviceId", "RiskScore", "OnboardingStatus", "AzureID"],
    "ip": ["Address"],
    "file": ["Name", "Directory"],
    "filehash": ["Algorithm", "Value"],
    "process": ["CommandLine", "ProcessId", "CreatedTimeUtc"],
    "url": ["Url"],
    "malware": ["Name", "Category"],
    "registry-key": ["Hive", "Key"],
    "registry-value": ["Name", "Value"],
    "cloud-application": ["Name", "AppId"],
    "mailbox": ["MailboxPrimaryAddress", "Upn"],
    "security-group": ["DistinguishedName", "SID"],
    "azure-resource": ["ResourceId"],
    "dns": ["DomainName"],
}

# Keys whose values are themselves entities and must be walked.
_NESTED_KEYS = [
    "ImageFile", "ParentProcess", "FileHashes", "LastIpAddress",
    "LastExternalIpAddress", "Host", "Account", "Process", "File",
]


def _normalise_kind(ent: dict) -> str:
    kind = str(ent.get("Type") or ent.get("$type") or "").lower()
    kind = kind.split(".")[-1].replace("entity", "").strip()
    return kind or "unknown"


def parse_entities(raw: Any) -> list[dict[str, Any]]:
    """Flatten the SecurityAlert Entities blob.

    Three quirks this handles, all seen in real Defender/Sentinel alerts:
    entity types are lowercase strings on a `Type` key; the blob uses
    `$id`/`$ref` back-references, so `{"$ref": "7"}` stubs carry no data and
    must be skipped; and the entities that matter are frequently nested —
    a host's IP addresses and a process's image file are children, not
    siblings, so the walk has to recurse.
    """
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if isinstance(raw, dict):
        raw = [raw]

    out: list[dict[str, Any]] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 4 or not isinstance(node, dict):
            return
        # A pure back-reference carries no data of its own.
        if set(node.keys()) == {"$ref"}:
            return

        kind = _normalise_kind(node)
        fields = {
            k: node[k]
            for k in _ENTITY_FIELDS.get(kind, [])
            if node.get(k) not in (None, "", [], {})
        }
        if fields:
            out.append({"type": kind, **fields})

        for key in _NESTED_KEYS:
            child = node.get(key)
            if isinstance(child, dict):
                walk(child, depth + 1)
            elif isinstance(child, list):
                for item in child:
                    walk(item, depth + 1)

    for ent in raw:
        walk(ent)
    return out


INCIDENT_QUERY = """
SecurityIncident
| where IncidentNumber == {number}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, IncidentName, Title, Description, Severity, Status,
          Classification, ClassificationReason, ClassificationComment,
          CreatedTime, ClosedTime, Owner, AlertIds, IncidentUrl, ProviderName,
          Labels
"""

ALERTS_QUERY = """
SecurityAlert
| where SystemAlertId in ({ids})
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, Description, Tactics,
          Techniques, ProductName, VendorName, Entities, StartTime, EndTime
"""


# Investigation value by entity type. Accounts, hosts, IPs and URLs drive
# triage; a domain controller's normal process and hash inventory is noise
# that pushes real signal out of the model's context.
_ENTITY_PRIORITY = {
    "account": 0, "host": 1, "ip": 2, "url": 3, "azure-resource": 4,
    "mailbox": 5, "cloud-application": 6, "registry-key": 7, "registry-value": 8,
    "malware": 9, "process": 10, "file": 11, "filehash": 12,
}
_ENTITY_TYPE_CAP = {"process": 6, "file": 6, "filehash": 4}
_ENTITY_TOTAL_CAP = 30


def _prioritise_entities(entities: list[dict]) -> list[dict]:
    """Rank by investigation value and cap the low-value, high-volume types."""
    ordered = sorted(entities, key=lambda e: _ENTITY_PRIORITY.get(e["type"], 99))
    per_type: dict[str, int] = {}
    kept = []
    for e in ordered:
        t = e["type"]
        cap = _ENTITY_TYPE_CAP.get(t)
        per_type[t] = per_type.get(t, 0) + 1
        if cap and per_type[t] > cap:
            continue
        kept.append(e)
        if len(kept) >= _ENTITY_TOTAL_CAP:
            break
    return kept


def build_envelope(incident_number: int, days: int = 14) -> dict[str, Any]:
    """Resolve an incident into a self-contained evidence object."""
    inc_rows = run_kql(INCIDENT_QUERY.format(number=incident_number), days=days)
    if not inc_rows:
        raise LookupError(f"incident {incident_number} not found in last {days}d")
    inc = inc_rows[0]

    alert_ids = inc.get("AlertIds") or []
    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except json.JSONDecodeError:
            alert_ids = []

    alerts, entities = [], []
    if alert_ids:
        quoted = ",".join(f'"{a}"' for a in alert_ids[:20])
        for a in run_kql(ALERTS_QUERY.format(ids=quoted), days=days):
            entities.extend(parse_entities(a.pop("Entities", None)))
            alerts.append(a)

    # Deduplicate entities on their full field set.
    seen, unique = set(), []
    for e in entities:
        key = json.dumps(e, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    unique = _prioritise_entities(unique)

    return {
        "schema_version": "1.0",
        "incident": {
            k: inc.get(k)
            for k in (
                "IncidentNumber", "IncidentName", "Title", "Description", "Severity",
                "Status", "CreatedTime", "Owner", "ProviderName", "IncidentUrl",
            )
        },
        "alerts": alerts,
        "entities": unique,
        # Held out of the model's view during backtesting; used only for scoring.
        "_label": {
            "Classification": inc.get("Classification"),
            "ClassificationReason": inc.get("ClassificationReason"),
            "ClosedTime": inc.get("ClosedTime"),
        },
    }


def model_view(envelope: dict) -> dict:
    """Strip the held-out label before the envelope reaches the model."""
    return {k: v for k, v in envelope.items() if not k.startswith("_")}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python envelope.py <IncidentNumber>")
        raise SystemExit(1)

    env = build_envelope(int(sys.argv[1]), days=config.HISTORY_DAYS)
    print(json.dumps(model_view(env), indent=2, default=str))

    inc = env["incident"]
    print("\n--- sanity check ---")
    print(f"incident name (ARM id): {inc.get('IncidentName') or 'MISSING'}")
    print(f"alerts parsed:          {len(env['alerts'])}")
    print(f"entities parsed:        {len(env['entities'])}")
    if env["entities"]:
        from collections import Counter

        for kind, n in Counter(e["type"] for e in env["entities"]).most_common():
            print(f"  {kind:<18} {n}")
    else:
        print("  NO ENTITIES PARSED — parse_entities needs work for this alert product,")
        print("  and both the agent and the labeling view will be degraded until it does.")
