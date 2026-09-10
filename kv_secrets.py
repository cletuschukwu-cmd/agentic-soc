"""Secret management via Azure Key Vault.

The single interface for every secret the platform needs — Defender API client
secrets, external threat-intel API keys, anything else. No secret ever lives in
code, a config file, an environment variable, or the repo. Code calls
get_secret("name") and this module fetches it from Key Vault at runtime.

Identity model, consistent with the rest of the platform:
  * Locally, DefaultAzureCredential uses your `az login`.
  * Deployed, it uses the app's managed identity.
  Neither path stores a secret to read secrets — the credential is the identity,
  and the identity is granted Key Vault Secrets User on the vault.

Per-customer vaults: the vault name comes from the customer profile
(extra.key_vault) so each customer's secrets live in their own vault, or from
AISOC_KEY_VAULT for local dev. Cloud-aware: the vault URI suffix differs between
Azure Commercial (vault.azure.net) and Azure Government (vault.usgovcloudapi.net).
"""

from __future__ import annotations

import os
from functools import lru_cache

from customer import customer

# Vault DNS suffix by cloud — the one endpoint difference between clouds.
_VAULT_SUFFIX = {
    "commercial": "vault.azure.net",
    "government": "vault.usgovcloudapi.net",
}


def _vault_uri() -> str:
    name = os.environ.get("AISOC_KEY_VAULT") or customer().extra.get("key_vault")
    if not name:
        raise RuntimeError(
            "no Key Vault configured. Set AISOC_KEY_VAULT or add 'key_vault' to "
            "the customer profile.")
    suffix = _VAULT_SUFFIX.get(customer().cloud, _VAULT_SUFFIX["commercial"])
    return f"https://{name}.{suffix}/"


@lru_cache(maxsize=1)
def _client():
    # Imported lazily so modules that never touch secrets don't require the SDK.
    from azure.keyvault.secrets import SecretClient
    return SecretClient(vault_url=_vault_uri(), credential=customer().credential())


@lru_cache(maxsize=64)
def get_secret(name: str) -> str:
    """Fetch a secret by name from the customer's Key Vault. Cached for the
    process lifetime — secrets are read once, not on every call."""
    return _client().get_secret(name).value


def get_secret_optional(name: str, default: str | None = None) -> str | None:
    """Like get_secret, but returns default instead of raising if the secret is
    absent — for secrets that may or may not be configured for a customer."""
    try:
        return get_secret(name)
    except Exception:  # noqa: BLE001
        return default


def clear_cache() -> None:
    """Drop cached secrets (e.g. after a rotation). Next read re-fetches."""
    get_secret.cache_clear()
    _client.cache_clear()


if __name__ == "__main__":
    import sys
    # Smoke test: read a secret by name, or list nothing sensitive.
    try:
        print("vault:", _vault_uri())
    except Exception as e:  # noqa: BLE001
        print("vault not configured:", e)
        sys.exit(1)
    if len(sys.argv) > 1:
        name = sys.argv[1]
        try:
            val = get_secret(name)
            print(f"secret '{name}' read OK, length {len(val)}")
        except Exception as e:  # noqa: BLE001
            print(f"could not read '{name}': {e}")
