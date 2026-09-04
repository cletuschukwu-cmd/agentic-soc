"""Source registry — the platform's evidence abstraction.

A "source" is anything the agent can draw evidence from: a Log Analytics table,
a JSON blob in storage, a raw file, an external intel API (Google TI,
VirusTotal, MISP), a CVE database. Tools never know which. They ask the
registry for a logical capability — "network_events", "threat_intel",
"sensitive_documents" — and the registry resolves it to a concrete source and
executes the query through the right transport.

Two axes describe every source:

  kind  — the transport. How the data is physically reached.
            kql        a Log Analytics / ADX table          (live today)
            storage    a blob / file in object storage      (shaped, dormant)
            rest_api   an external HTTP API                  (shaped, dormant)
            file       a local or mounted file              (shaped, dormant)

  mode  — freshness policy, independent of kind.
            live       queried per investigation
            ingested   pulled on a schedule into a local store, queried there

Governance rules enforced here, once, for the whole platform:
  * Gov tenants may not use live rest_api sources (no outbound egress). The
    registry refuses to execute them and reports the reason.
  * Commercial defaults to live for external sources but every source may
    override its mode.
  * Per-source override always wins over the tenant default.

This is the single control point for source auth, availability, mode policy,
and (as the platform grows) rate-limiting, caching, and cost. Scale comes from
adding registry entries at onboarding, never from changing tool code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from customer import customer
import schema  # the kql table resolver; kql kind delegates to it


# --- Source descriptor ------------------------------------------------------

@dataclass(frozen=True)
class Source:
    logical: str          # capability name tools ask for, e.g. "threat_intel"
    kind: str             # kql | storage | rest_api | file
    mode: str             # live | ingested
    target: str           # table name, blob path, API base, etc.
    available: bool       # is it usable for this customer right now
    reason: str = ""      # if unavailable, why


# --- Mode policy ------------------------------------------------------------

def _effective_mode(kind: str, declared_mode: str | None) -> str:
    """Resolve a source's mode against tenant governance.

    Gov + live rest_api is forbidden; force ingested. Otherwise honor the
    per-source declaration, falling back to the tenant-appropriate default.
    """
    is_gov = customer().cloud == "government"
    if kind == "rest_api" and is_gov:
        return "ingested"                     # enforced constraint
    if declared_mode:
        return declared_mode                  # per-source override wins
    if kind == "rest_api":
        return "live" if not is_gov else "ingested"   # commercial default: live
    return "live"                             # kql/storage/file default: live


# --- Resolution -------------------------------------------------------------

def resolve(logical: str) -> Source:
    """Resolve a logical capability to a concrete Source for this customer.

    Reads the customer's `sources` registry from their profile if present;
    otherwise falls back to the kql schema map (so existing kql sources work
    with no extra configuration).
    """
    registry: dict[str, dict] = customer().extra.get("sources", {}) or {}

    if logical in registry:
        spec = registry[logical]
        kind = spec.get("kind", "kql")
        mode = _effective_mode(kind, spec.get("mode"))
        target = spec.get("target", "")
        is_gov = customer().cloud == "government"
        # Governance: a Gov source declared live rest_api is downgraded, and if
        # no ingested target exists it is unavailable rather than silently wrong.
        if kind == "rest_api" and is_gov and spec.get("mode") == "live" and not spec.get("ingested_target"):
            return Source(logical, kind, "ingested", "", False,
                          "live external APIs are not permitted in Azure Government "
                          "and no ingested fallback is configured")
        if mode == "ingested" and spec.get("ingested_target"):
            target = spec["ingested_target"]
        return Source(logical, kind, mode, target, bool(target),
                      "" if target else "no target configured")

    # Fall back to the kql schema map for logical sources it knows.
    if schema.has(logical):
        return Source(logical, "kql", "live", schema.table(logical), True)
    if logical in schema.CANDIDATE_TABLES:
        return Source(logical, "kql", "live", "", False,
                      "no table with data for this source in the customer workspace")

    return Source(logical, "unknown", "", "", False, f"unknown logical source '{logical}'")


def has(logical: str) -> bool:
    return resolve(logical).available


def available_sources() -> list[dict[str, Any]]:
    """Everything this customer can currently draw evidence from."""
    seen = set()
    out = []
    registry = customer().extra.get("sources", {}) or {}
    for logical in list(registry) + schema.available_sources():
        if logical in seen:
            continue
        seen.add(logical)
        s = resolve(logical)
        out.append({"logical": s.logical, "kind": s.kind, "mode": s.mode,
                    "available": s.available, "reason": s.reason})
    return sorted(out, key=lambda x: (not x["available"], x["logical"]))


# --- Transport execution ----------------------------------------------------
#
# Each kind has a handler. Only kql is implemented today; the others are
# registered as explicit "not yet built" so a tool gets a clean, honest result
# instead of a crash when it reaches for a dormant transport.

def _exec_kql(source: Source, query_fragment: str, days: int) -> dict[str, Any]:
    from envelope import run_kql
    q = query_fragment.replace("{table}", source.target)
    try:
        rows = run_kql(q, days=days)
        return {"available": True, "kind": "kql", "mode": source.mode,
                "source": source.logical, "row_count": len(rows), "rows": rows}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "kind": "kql", "source": source.logical,
                "reason": str(exc)[:200], "rows": []}


def _not_yet(kind: str) -> Callable:
    def handler(source: Source, *_args, **_kwargs) -> dict[str, Any]:
        return {"available": False, "kind": kind, "source": source.logical,
                "reason": f"{kind} transport is registered but not yet implemented",
                "rows": []}
    return handler


_HANDLERS: dict[str, Callable] = {
    "kql": _exec_kql,
    "storage": _not_yet("storage"),
    "rest_api": _not_yet("rest_api"),
    "file": _not_yet("file"),
}


def query(logical: str, query_fragment: str, days: int = 7) -> dict[str, Any]:
    """Execute against a logical source, whatever its transport.

    For kql sources, query_fragment is KQL using {table} as a placeholder for
    the resolved table name. Tools stay transport-agnostic: they call query()
    and never branch on kind.
    """
    source = resolve(logical)
    if not source.available:
        return {"available": False, "source": logical, "reason": source.reason, "rows": []}
    handler = _HANDLERS.get(source.kind)
    if handler is None:
        return {"available": False, "source": logical,
                "reason": f"no handler for kind '{source.kind}'", "rows": []}
    return handler(source, query_fragment, days)


if __name__ == "__main__":
    print(f"customer: {customer().name}  cloud: {customer().cloud}\n")
    print("logical source        kind      mode      available")
    print("-" * 56)
    for s in available_sources():
        flag = "yes" if s["available"] else f"no  ({s['reason'][:30]})"
        print(f"{s['logical']:<21} {s['kind']:<9} {s['mode']:<9} {flag}")
