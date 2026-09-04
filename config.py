"""Compatibility shim over customer.py.

The codebase originally read cloud and workspace settings from this module.
Portability now lives in customer.py, where one profile file per tenant holds
everything customer-specific. This shim keeps the old `config.X` names working
by delegating to the active customer profile, so no other file had to change.

New code should prefer `from customer import customer` and read fields off the
returned profile. This module remains for the existing imports.
"""

from customer import (  # noqa: F401
    ALLOWED_TABLES,
    AGENT_BUDGET_SECONDS,
    HISTORY_DAYS,
    MAX_QUERY_TIMESPAN_DAYS,
    MAX_ROWS,
    MAX_TIMESPAN_DAYS,
    TOOL_TIMEOUT_SECONDS,
    customer,
    require,
)


class _Profile:
    """Adapts a Customer to the old `config.profile()` surface."""

    def __init__(self, c):
        self._c = c

    name = property(lambda self: self._c.cloud)
    authority = property(lambda self: self._c.authority)
    aoai_scope = property(lambda self: self._c.aoai_scope)
    logs_endpoint = property(lambda self: self._c.logs_endpoint)
    arm_endpoint = property(lambda self: self._c.arm_endpoint)
    graph_endpoint = property(lambda self: self._c.graph_endpoint)
    graph_scope = property(lambda self: self._c.graph_scope)


def profile():
    return _Profile(customer())


def credential():
    return customer().credential()


# Module-level names the old code reads directly. These are functions of the
# active profile, resolved on attribute access via __getattr__ below.
def __getattr__(name: str):
    c = customer()
    mapping = {
        "WORKSPACE_ID": c.workspace_id,
        "AOAI_ENDPOINT": c.aoai_endpoint,
        "AOAI_API_VERSION": c.aoai_api_version,
        "MODEL_DEPLOYMENT": c.model_deployment,
        "REASONING_EFFORT": c.reasoning_effort,
        "SUBSCRIPTION_ID": c.subscription_id,
        "RESOURCE_GROUP": c.resource_group,
        "WORKSPACE_NAME": c.workspace_name,
        "SENTINEL_API_VERSION": c.sentinel_api_version,
        "INCIDENT_LABEL": c.incident_label,
        "POLL_MINUTES": c.poll_minutes,
        "POLL_MAX_INCIDENTS": c.poll_max_incidents,
    }
    if name in mapping:
        return mapping[name]
    raise AttributeError(f"module 'config' has no attribute '{name}'")
