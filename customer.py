"""Per-customer configuration.

Everything that differs between one customer and the next lives in a single
profile file, not in code and not in scattered environment variables. To
onboard a second customer you copy customers/example.json, fill in their
values, and point AISOC_CUSTOMER at it. Nothing in the codebase changes.

That is the whole portability story: one file per tenant.

Resolution order for the active profile:
  1. AISOC_CUSTOMER names a profile in the customers/ directory
     (AISOC_CUSTOMER=acme  ->  customers/acme.json)
  2. AISOC_CUSTOMER_FILE gives an explicit path to a profile
  3. otherwise, fall back to individual AISOC_* environment variables
     (the original behaviour, useful for a dev box)
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from azure.identity import AzureAuthorityHosts, DefaultAzureCredential

CUSTOMERS_DIR = Path(os.environ.get("AISOC_CUSTOMERS_DIR", "customers"))


# --- Cloud endpoints, keyed by cloud name ----------------------------------

_CLOUDS = {
    "commercial": {
        "authority": AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
        "aoai_scope": "https://cognitiveservices.azure.com/.default",
        "logs_endpoint": "https://api.loganalytics.io/v1",
        "arm_endpoint": "https://management.azure.com",
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
        "graph_scope": "https://graph.microsoft.com/.default",
    },
    "government": {
        "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
        "aoai_scope": "https://cognitiveservices.azure.us/.default",
        "logs_endpoint": "https://api.loganalytics.us/v1",
        "arm_endpoint": "https://management.usgovcloudapi.net",
        "graph_endpoint": "https://graph.microsoft.us/v1.0",
        "graph_scope": "https://graph.microsoft.us/.default",
    },
}


@dataclass(frozen=True)
class Customer:
    """One customer's complete configuration."""

    name: str
    cloud: str
    workspace_id: str
    aoai_endpoint: str
    model_deployment: str
    # Needed only for incident writeback.
    subscription_id: str = ""
    resource_group: str = ""
    workspace_name: str = ""
    # Behaviour knobs with sensible defaults; a customer can override any.
    aoai_api_version: str = "2024-10-21"
    sentinel_api_version: str = "2024-03-01"
    incident_label: str = "ai-triaged"
    poll_minutes: int = 15
    poll_max_incidents: int = 10
    reasoning_effort: str = "medium"
    extra: dict[str, Any] = field(default_factory=dict)

    # Cloud-derived values -------------------------------------------------
    @property
    def _cloud(self) -> dict:
        if self.cloud not in _CLOUDS:
            raise ValueError(f"unknown cloud '{self.cloud}' (expected commercial|government)")
        return _CLOUDS[self.cloud]

    @property
    def authority(self) -> str:
        return self._cloud["authority"]

    @property
    def aoai_scope(self) -> str:
        return self._cloud["aoai_scope"]

    @property
    def logs_endpoint(self) -> str:
        return self._cloud["logs_endpoint"]

    @property
    def arm_endpoint(self) -> str:
        return self._cloud["arm_endpoint"]

    @property
    def graph_endpoint(self) -> str:
        return self._cloud["graph_endpoint"]

    @property
    def graph_scope(self) -> str:
        return self._cloud["graph_scope"]

    def credential(self) -> DefaultAzureCredential:
        return DefaultAzureCredential(authority=self.authority)


def _from_env() -> Customer:
    """Fallback: build a profile from individual environment variables."""
    return Customer(
        name=os.environ.get("AISOC_CUSTOMER_NAME", "env"),
        cloud=os.environ.get("AISOC_CLOUD", "commercial"),
        workspace_id=os.environ.get("AISOC_WORKSPACE_ID", ""),
        aoai_endpoint=os.environ.get("AISOC_AOAI_ENDPOINT", ""),
        model_deployment=os.environ.get("AISOC_MODEL_DEPLOYMENT", "gpt-5.6-sol"),
        subscription_id=os.environ.get("AISOC_SUBSCRIPTION_ID", ""),
        resource_group=os.environ.get("AISOC_RESOURCE_GROUP", ""),
        workspace_name=os.environ.get("AISOC_WORKSPACE_NAME", ""),
        aoai_api_version=os.environ.get("AISOC_AOAI_API_VERSION", "2024-10-21"),
    )


def _from_file(path: Path) -> Customer:
    data = json.loads(path.read_text())
    known = {f for f in Customer.__dataclass_fields__ if f != "extra"}
    kwargs = {k: v for k, v in data.items() if k in known}
    kwargs["extra"] = {k: v for k, v in data.items() if k not in known}
    missing = [f for f in ("name", "cloud", "workspace_id", "aoai_endpoint",
                           "model_deployment") if not kwargs.get(f)]
    if missing:
        raise ValueError(f"profile {path} missing required fields: {missing}")
    return Customer(**kwargs)


_active: Customer | None = None


def customer() -> Customer:
    """The active customer profile, resolved once and cached."""
    global _active
    if _active is not None:
        return _active

    named = os.environ.get("AISOC_CUSTOMER")
    explicit = os.environ.get("AISOC_CUSTOMER_FILE")

    if named:
        path = CUSTOMERS_DIR / f"{named}.json"
        if not path.exists():
            raise FileNotFoundError(f"no profile for customer '{named}' at {path}")
        _active = _from_file(path)
    elif explicit:
        _active = _from_file(Path(explicit))
    else:
        _active = _from_env()
    return _active


def require(name: str, value: str) -> str:
    if not value:
        raise RuntimeError(
            f"{name} is not set for customer '{customer().name}'. "
            f"Add it to the customer profile or set the environment variable."
        )
    return value


# --- Guardrails (uniform across customers unless overridden in `extra`) -----

ALLOWED_TABLES = {
    "SecurityIncident", "SecurityAlert", "IdentityInfo", "DeviceInfo",
    "SigninLogs", "AuditLogs", "DeviceNetworkEvents", "DeviceProcessEvents",
    "AADNonInteractiveUserSignInLogs",
}
MAX_ROWS = 50
MAX_TIMESPAN_DAYS = 14
MAX_QUERY_TIMESPAN_DAYS = 180
HISTORY_DAYS = 90
TOOL_TIMEOUT_SECONDS = 30
AGENT_BUDGET_SECONDS = 90


def list_customers() -> list[str]:
    if not CUSTOMERS_DIR.exists():
        return []
    return sorted(p.stem for p in CUSTOMERS_DIR.glob("*.json"))


if __name__ == "__main__":
    print("customers directory:", CUSTOMERS_DIR.resolve())
    print("profiles found:", list_customers() or "(none)")
    try:
        c = customer()
        print(f"\nactive profile: {c.name}")
        print(f"  cloud            {c.cloud}")
        print(f"  workspace        {c.workspace_id}")
        print(f"  model            {c.model_deployment}")
        print(f"  logs endpoint    {c.logs_endpoint}")
        print(f"  aoai endpoint    {c.aoai_endpoint}")
    except Exception as exc:  # noqa: BLE001
        print(f"\nno active profile resolved: {exc}")
