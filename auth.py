"""Authentication and authorization boundary.

Security-first design for a government-cloud enterprise application. Every
principle here is built to be Entra-ID-correct from day one; only the identity
*issuer* is stubbed for local development, and that stub is designed so real
Entra OIDC drops into the same seam without touching the rest of the app.

Non-negotiable properties, enforced here:

  * Reject by default. A request with no valid identity is refused. "No auth"
    can never be the accidental production state — it takes an explicit,
    loud opt-in (AISOC_AUTH_MODE=dev) that logs a warning on every use.
  * Two identities, cleanly separated. The USER identity (this module) governs
    who may ask and what they may do. The BACKEND identity (managed identity,
    elsewhere) does the actual querying. A compromised browser never becomes a
    compromised workspace.
  * Least privilege for people, mirroring least privilege for agents. Roles
    (analyst / lead / auditor) gate what a user may do, just as allowed_sources
    gates what an agent may touch.
  * Auditable. Every authenticated principal is available to be logged against
    every action. In government, "who ran this against our security data" is a
    compliance requirement, not a nicety.

Replacing the stub with real Entra:
  Set AISOC_AUTH_MODE=entra and provide AISOC_ENTRA_TENANT_ID,
  AISOC_ENTRA_AUDIENCE (the app registration's client id), and the Gov
  authority. The verify path then validates the JWT signature against Entra's
  published keys, the issuer, the audience, and expiry, and reads roles from
  the token's `roles` / `groups` claims. Nothing else in the app changes.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("aisoc.auth")


# --- Roles ------------------------------------------------------------------

class Role(str, Enum):
    ANALYST = "analyst"   # run investigations, see verdicts
    LEAD = "lead"         # everything analyst can, plus (future) tuning/config
    AUDITOR = "auditor"   # read-only: view results and audit logs, cannot run

    @classmethod
    def from_claims(cls, raw_roles: list[str]) -> set["Role"]:
        out = set()
        for r in raw_roles or []:
            r = str(r).lower().strip()
            for role in cls:
                if role.value == r:
                    out.add(role)
        return out


# What each capability requires. Endpoints check against this, so authorization
# lives in one place, not scattered across the app.
class Capability(str, Enum):
    RUN_INVESTIGATION = "run_investigation"
    VIEW_RESULTS = "view_results"
    VIEW_AUDIT = "view_audit"
    MANAGE_CONFIG = "manage_config"


_CAPABILITY_ROLES: dict[Capability, set[Role]] = {
    Capability.RUN_INVESTIGATION: {Role.ANALYST, Role.LEAD},
    Capability.VIEW_RESULTS: {Role.ANALYST, Role.LEAD, Role.AUDITOR},
    Capability.VIEW_AUDIT: {Role.LEAD, Role.AUDITOR},
    Capability.MANAGE_CONFIG: {Role.LEAD},
}


# --- Principal --------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """An authenticated user. What the app knows about who is asking."""
    subject: str            # stable user id (Entra oid)
    display_name: str
    roles: set[Role] = field(default_factory=set)
    tenant: str = ""
    auth_mode: str = "dev"

    def can(self, capability: Capability) -> bool:
        allowed = _CAPABILITY_ROLES.get(capability, set())
        return bool(self.roles & allowed)

    def audit_dict(self) -> dict:
        return {"subject": self.subject, "display_name": self.display_name,
                "roles": sorted(r.value for r in self.roles),
                "tenant": self.tenant, "auth_mode": self.auth_mode}


class AuthError(Exception):
    """Raised when authentication fails. Endpoints turn this into 401."""


class ForbiddenError(Exception):
    """Raised when an authenticated user lacks the capability. -> 403."""


# --- Verification -----------------------------------------------------------

AUTH_MODE = os.environ.get("AISOC_AUTH_MODE", "dev")


def _verify_dev(token: str | None) -> Principal:
    """Development stub. NOT for production.

    Accepts a shared dev key and grants a synthetic analyst+lead principal, so
    the app is exercisable locally before Entra is wired. Loudly warns on every
    call so it can never be mistaken for real auth, and still REJECTS a wrong or
    missing key — reject-by-default holds even in dev.
    """
    expected = os.environ.get("AISOC_DEV_KEY", "")
    if not expected:
        raise AuthError("dev auth mode requires AISOC_DEV_KEY to be set")
    if token != expected:
        raise AuthError("invalid or missing dev key")
    log.warning("AUTH: using DEV stub identity — not real authentication. "
                "Set AISOC_AUTH_MODE=entra for production.")
    # Dev principal carries analyst+lead so the console is fully exercisable.
    return Principal(
        subject="dev-user", display_name="Dev Analyst (stub)",
        roles={Role.ANALYST, Role.LEAD}, tenant="dev", auth_mode="dev",
    )


def _verify_entra(token: str | None) -> Principal:
    """Real Entra ID (Azure Government) validation.

    Deliberately not implemented until the app registration exists. Raising a
    clear error here (rather than silently allowing) preserves reject-by-default
    the moment someone flips to entra mode without finishing setup.

    When implemented, this will:
      1. fetch Entra's signing keys (JWKS) for the Gov tenant, cached
      2. validate the JWT signature, issuer, audience, expiry, nbf
      3. read subject (oid), name, and roles from `roles`/`groups` claims
      4. return a Principal — same shape the rest of the app already uses
    """
    raise AuthError(
        "entra auth mode is selected but not yet implemented. Provide the app "
        "registration and JWKS validation, or use AISOC_AUTH_MODE=dev locally."
    )


def authenticate(token: str | None) -> Principal:
    """Resolve a bearer token to a Principal, or raise AuthError.

    This is the single entry point. Reject-by-default: an unknown auth mode or
    any failure raises, never returns an anonymous principal.
    """
    if AUTH_MODE == "entra":
        return _verify_entra(token)
    if AUTH_MODE == "dev":
        return _verify_dev(token)
    raise AuthError(f"unknown AISOC_AUTH_MODE '{AUTH_MODE}' (expected dev|entra)")


def require(principal: Principal, capability: Capability) -> None:
    """Enforce that a principal holds a capability, or raise ForbiddenError."""
    if not principal.can(capability):
        raise ForbiddenError(
            f"user '{principal.display_name}' with roles "
            f"{sorted(r.value for r in principal.roles)} lacks capability "
            f"'{capability.value}'")


if __name__ == "__main__":
    # Demonstrate the boundary without a web server.
    os.environ.setdefault("AISOC_DEV_KEY", "dev-key")
    print("auth mode:", AUTH_MODE)

    print("\nreject-by-default:")
    for bad in (None, "", "wrong"):
        try:
            authenticate(bad)
            print(f"  token={bad!r} -> ALLOWED (WRONG)")
        except AuthError as e:
            print(f"  token={bad!r} -> refused: {e}")

    print("\nvalid dev key:")
    p = authenticate("dev-key")
    print("  principal:", p.audit_dict())

    print("\ncapability checks:")
    for cap in Capability:
        print(f"  {cap.value:<20} -> {'allow' if p.can(cap) else 'deny'}")
