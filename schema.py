"""Per-customer schema capability map.

The portability problem: every customer's Log Analytics workspace holds
different tables. One customer has DeviceNetworkEvents; another renamed it,
uses a different EDR, or hasn't onboarded endpoint data at all. A tool that
hardcodes a table name works in your lab and breaks at the first customer.

The fix, in two parts:

1. Logical sources. Tools ask for a capability — "network_events",
   "identity_info", "threat_intel" — never a raw table name. This module maps
   each logical source to the real table for the active customer.

2. Discovery. schema_probe() introspects the customer's workspace, finds which
   candidate tables exist and hold data, and writes the resolved map into their
   profile. Onboarding a new customer is: run discovery once, review, save.

A tool checks `has(source)` before querying and calls `table(source)` to get
the real name. If a customer lacks a source, the tool reports it cleanly
instead of erroring on a missing table.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from customer import CUSTOMERS_DIR, customer
from envelope import run_kql

# Logical source -> ordered list of candidate real tables. First one that
# exists and has data in a given tenant wins. Order reflects preference:
# the richest/most-standard table first, fallbacks after.
CANDIDATE_TABLES: dict[str, list[str]] = {
    "incidents":        ["SecurityIncident"],
    "alerts":           ["SecurityAlert"],
    "identity_info":    ["IdentityInfo"],
    "device_info":      ["DeviceInfo"],
    "signins":          ["SigninLogs"],
    "noninteractive_signins": ["AADNonInteractiveUserSignInLogs"],
    "audit":            ["AuditLogs"],
    "network_events":   ["DeviceNetworkEvents", "CommonSecurityLog"],
    "process_events":   ["DeviceProcessEvents"],
    "file_events":      ["DeviceFileEvents"],
    "logon_events":     ["DeviceLogonEvents", "SigninLogs"],
    "device_events":    ["DeviceEvents"],
    "threat_intel":     ["ThreatIntelIndicators", "ThreatIntelligenceIndicator"],
    "firewall":         ["CommonSecurityLog"],
}


def _resolved_map() -> dict[str, str]:
    """The customer's saved logical->table map, or empty if not yet probed."""
    return customer().extra.get("schema_map", {}) or {}


def has(source: str) -> bool:
    """True if the active customer has a real table for this logical source."""
    return bool(_resolved_map().get(source))


def table(source: str) -> str:
    """Resolve a logical source to the customer's real table name.

    Raises if the source is not available for this customer, so a tool can
    catch it and report 'source not available' rather than querying a table
    that does not exist.
    """
    resolved = _resolved_map().get(source)
    if not resolved:
        # Fall back to the first candidate so a lab without a saved map still
        # works; discovery replaces this with the verified table.
        candidates = CANDIDATE_TABLES.get(source, [])
        if candidates:
            return candidates[0]
        raise KeyError(f"no candidate table known for logical source '{source}'")
    return resolved


def available_sources() -> list[str]:
    return sorted(k for k, v in _resolved_map().items() if v)


def schema_probe(days: int = 30) -> dict[str, Any]:
    """Introspect the active customer's workspace.

    For each logical source, find the first candidate table that exists and
    has data. Returns a report and the resolved map. Does not write anything;
    call save_schema_map() to persist.
    """
    resolved: dict[str, str] = {}
    report: list[dict[str, Any]] = []

    for source, candidates in CANDIDATE_TABLES.items():
        chosen, rows_found, detail = None, 0, []
        for t in candidates:
            try:
                r = run_kql(f"{t} | where TimeGenerated > ago({days}d) | count", days=days)
                n = r[0].get("Count", 0) if r else 0
                detail.append({"table": t, "rows": n})
                if n > 0 and chosen is None:
                    chosen, rows_found = t, n
            except Exception as exc:  # noqa: BLE001
                detail.append({"table": t, "rows": None, "error": str(exc)[:60]})
        if chosen:
            resolved[source] = chosen
        report.append(
            {"source": source, "resolved_to": chosen, "rows": rows_found, "candidates": detail}
        )

    return {
        "customer": customer().name,
        "window_days": days,
        "available": sorted(resolved.keys()),
        "missing": sorted(set(CANDIDATE_TABLES) - set(resolved)),
        "schema_map": resolved,
        "report": report,
    }


def save_schema_map(schema_map: dict[str, str]) -> Path:
    """Write the resolved map into the customer's profile file, under
    extra.schema_map, so tools use it on the next run."""
    c = customer()
    path = CUSTOMERS_DIR / f"{c.name}.json"
    if not path.exists():
        raise FileNotFoundError(f"profile file not found: {path}")
    data = json.loads(path.read_text())
    data["schema_map"] = schema_map
    path.write_text(json.dumps(data, indent=2))
    return path


def enumerate_tables(days: int = 30) -> list[dict[str, Any]]:
    """Every table in the customer's workspace that has data in the window.

    This is the full inventory, not the curated candidate set. It feeds the
    discover-then-approve access model: nothing here is queryable by the agent
    until a human approves it into the customer's allowlist.
    """
    q = f"""
    union withsource=_TableName *
    | where TimeGenerated > ago({days}d)
    | summarize Rows = count() by _TableName
    | order by Rows desc
    """
    try:
        rows = run_kql(q, days=days)
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)[:200]}]
    return [{"table": r["_TableName"], "rows": r["Rows"]} for r in rows]


def approved_tables() -> set[str]:
    """Tables a human has approved for agent query for this customer.

    Until approval happens, the curated schema-map tables are implicitly
    approved (they were vetted when the map was built); everything else is
    off-limits.
    """
    explicit = set(customer().extra.get("approved_tables", []) or [])
    curated = set(_resolved_map().values())
    return explicit | curated


def is_approved(table_name: str) -> bool:
    return table_name in approved_tables()


def save_approved_tables(tables: list[str]) -> Path:
    """Persist the human-approved query allowlist into the customer profile."""
    c = customer()
    path = CUSTOMERS_DIR / f"{c.name}.json"
    if not path.exists():
        raise FileNotFoundError(f"profile file not found: {path}")
    data = json.loads(path.read_text())
    data["approved_tables"] = sorted(set(tables))
    path.write_text(json.dumps(data, indent=2))
    return path


if __name__ == "__main__":
    import sys

    if "--enumerate" in sys.argv:
        print(f"full table inventory for {customer().name}:\n")
        inv = enumerate_tables()
        if inv and "error" in inv[0]:
            print("enumeration failed:", inv[0]["error"])
        else:
            curated = set(_resolved_map().values())
            approved = approved_tables()
            print(f"{'table':<42} {'rows':>10}  status")
            print("-" * 70)
            for row in inv:
                t = row["table"]
                status = "curated" if t in curated else (
                    "approved" if t in approved else "not approved")
                print(f"{t:<42} {row['rows']:>10}  {status}")
            print(f"\n{len(inv)} tables with data. "
                  f"{len(approved)} approved for agent query.")
            print("\nTo approve tables, add their names to \"approved_tables\" in the "
                  "customer profile, or use save_approved_tables() after review.")
        sys.exit(0)

    save = "--save" in sys.argv
    result = schema_probe()

    print(f"customer: {result['customer']}  (window {result['window_days']}d)\n")
    print("logical source        -> real table            rows")
    print("-" * 60)
    for row in result["report"]:
        arrow = row["resolved_to"] or "(none available)"
        rows = row["rows"] if row["resolved_to"] else ""
        print(f"{row['source']:<21} -> {arrow:<22} {rows}")

    print(f"\navailable: {len(result['available'])}   missing: {len(result['missing'])}")
    if result["missing"]:
        print("missing sources:", ", ".join(result["missing"]))

    if save:
        p = save_schema_map(result["schema_map"])
        print(f"\nschema map saved to {p}")
    else:
        print("\nrun with --save to write the map, or --enumerate for the full "
              "table inventory and approval status")
