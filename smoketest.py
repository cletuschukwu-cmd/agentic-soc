"""SDK smoke test.

Checks whether the two API surfaces this project depends on still exist in
whatever versions you have installed. Makes no network calls and touches no
Azure resources.

    python smoketest.py
"""

import sys


def check(label, fn):
    try:
        detail = fn()
        print(f"  PASS  {label}" + (f" ({detail})" if detail else ""))
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL  {label}\n        {type(exc).__name__}: {exc}")
        return False


print(f"python {sys.version.split()[0]}\n")
results = []

# --- azure-monitor-query ----------------------------------------------------
print("azure-monitor-query")


def versions():
    import azure.monitor.query as q
    import openai
    return f"query={getattr(q, '__version__', '?')} openai={openai.__version__}"


def logs_client_endpoint():
    """Construct the client for real. `endpoint` is accepted via **kwargs in
    1.x, so inspecting the signature gives a false negative."""
    from azure.monitor.query import LogsQueryClient

    class _FakeCred:
        def get_token(self, *scopes, **kwargs):
            raise RuntimeError("never called during construction")

    gov = "https://api.loganalytics.us/v1"
    client = LogsQueryClient(_FakeCred(), endpoint=gov)
    if client is None:
        raise RuntimeError("client construction returned None")
    return f"accepted endpoint={gov}"


def query_workspace_signature():
    import inspect
    from azure.monitor.query import LogsQueryClient

    params = inspect.signature(LogsQueryClient.query_workspace).parameters
    missing = [p for p in ("workspace_id", "query", "timespan") if p not in params]
    if missing:
        raise TypeError(f"query_workspace missing {missing}")
    return "workspace_id, query, timespan"


def status_enum():
    from azure.monitor.query import LogsQueryStatus

    for name in ("SUCCESS", "FAILURE"):
        if not hasattr(LogsQueryStatus, name):
            raise AttributeError(f"LogsQueryStatus.{name} missing")
    return "SUCCESS, FAILURE"


results.append(check("import + versions", versions))
results.append(check("LogsQueryClient(endpoint=...)", logs_client_endpoint))
results.append(check("query_workspace(...)", query_workspace_signature))
results.append(check("LogsQueryStatus", status_enum))

# --- openai -----------------------------------------------------------------
print("\nopenai")


def azure_client_signature():
    import inspect
    from openai import AzureOpenAI

    params = inspect.signature(AzureOpenAI.__init__).parameters
    missing = [
        p for p in ("azure_endpoint", "azure_ad_token_provider", "api_version") if p not in params
    ]
    if missing:
        raise TypeError(f"AzureOpenAI missing {missing}")
    return "azure_endpoint, azure_ad_token_provider, api_version"


def completions_path():
    from openai import AzureOpenAI

    if not hasattr(AzureOpenAI, "chat"):
        raise AttributeError("AzureOpenAI.chat removed")
    return "chat.completions available"


def token_provider():
    from azure.identity import get_bearer_token_provider  # noqa: F401

    return None


results.append(check("AzureOpenAI(...)", azure_client_signature))
results.append(check("chat.completions", completions_path))
results.append(check("get_bearer_token_provider", token_provider))

# --- verdict ----------------------------------------------------------------
print()
if all(results):
    print("All surfaces present. Your installed versions are fine — skip the venv,")
    print("widen the pins in requirements.txt, and run the baseline.")
else:
    print("At least one surface changed. Either pin to the older majors in a venv,")
    print("or paste this output back and the affected calls can be updated.")
    sys.exit(1)
