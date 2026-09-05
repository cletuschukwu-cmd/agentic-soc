"""Identity-compromise investigation tools.

Focused on answering "is this account compromised" — the questions a senior
analyst asks about an identity: how privileged is it, what's its risk state,
where has it signed in from, are there failed-then-success patterns, impossible
travel, MFA anomalies, risky sign-ins.

Every tool asks the source registry for a logical capability and fails soft.
"""

from typing import Any

import sources


def _q(logical: str, fragment: str, days: int) -> dict[str, Any]:
    return sources.query(logical, fragment, days=days)


def get_identity_profile(account: str, days: int = 7) -> dict[str, Any]:
    """Privilege, risk, roles and enablement for an account."""
    safe = account.replace("'", "")
    return _q(
        "identity_info",
        f"{{table}} | where AccountUPN =~ '{safe}' or AccountName =~ '{safe}' "
        f"| summarize arg_max(TimeGenerated, *) by AccountObjectId "
        f"| project AccountUPN, AccountObjectId, AccountName, AccountDomain, "
        f"IsAccountEnabled, UserType, AssignedRoles, GroupMembership, JobTitle, "
        f"Department, Manager, RiskLevel, RiskState, BlastRadius, IsServiceAccount",
        days,
    )


def get_signin_patterns(account: str, days: int = 7) -> dict[str, Any]:
    """Interactive sign-in behaviour: volume, failures, locations, apps, risk."""
    safe = account.replace("'", "")
    return _q(
        "signins",
        f"{{table}} | where UserPrincipalName =~ '{safe}' "
        f"| summarize Total=count(), "
        f"Failures=countif(ResultType != 0), "
        f"Success=countif(ResultType == 0), "
        f"Countries=make_set(tostring(LocationDetails.countryOrRegion), 15), "
        f"Cities=make_set(tostring(LocationDetails.city), 15), "
        f"IPs=dcount(IPAddress), "
        f"Apps=make_set(AppDisplayName, 15), "
        f"RiskySignins=countif(RiskLevelDuringSignIn in ('medium','high')), "
        f"MFAChallenged=countif(tostring(AuthenticationRequirement) == 'multiFactorAuthentication'), "
        f"FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)",
        days,
    )


def get_failed_then_success(account: str, days: int = 7) -> dict[str, Any]:
    """Failed sign-ins closely followed by success from the same IP — a
    password-spray / brute-force success signature."""
    safe = account.replace("'", "")
    return _q(
        "signins",
        f"{{table}} | where UserPrincipalName =~ '{safe}' "
        f"| summarize Failures=countif(ResultType != 0), "
        f"Successes=countif(ResultType == 0), "
        f"FailureReasons=make_set(ResultDescription, 10) "
        f"by IPAddress, tostring(LocationDetails.countryOrRegion) "
        f"| where Failures >= 3 and Successes >= 1 "
        f"| order by Failures desc",
        days,
    )


def get_risky_signins(account: str, days: int = 7) -> dict[str, Any]:
    """Individual medium/high risk sign-in events with detail, for citation."""
    safe = account.replace("'", "")
    return _q(
        "signins",
        f"{{table}} | where UserPrincipalName =~ '{safe}' "
        f"and RiskLevelDuringSignIn in ('medium','high') "
        f"| project TimeGenerated, Id, IPAddress, "
        f"Country=tostring(LocationDetails.countryOrRegion), "
        f"City=tostring(LocationDetails.city), AppDisplayName, "
        f"RiskLevelDuringSignIn, RiskState, RiskEventTypes, "
        f"ResultType, ConditionalAccessStatus "
        f"| order by TimeGenerated desc | take 25",
        days,
    )


def get_directory_changes(account: str, days: int = 7) -> dict[str, Any]:
    """Recent directory/audit activity on the account: role adds, MFA changes,
    password resets — the persistence moves after a compromise."""
    safe = account.replace("'", "")
    return _q(
        "audit",
        f"{{table}} | where TargetResources has '{safe}' or InitiatedBy has '{safe}' "
        f"| project TimeGenerated, OperationName, Category, Result, "
        f"Initiator=tostring(InitiatedBy), "
        f"Target=tostring(TargetResources) "
        f"| order by TimeGenerated desc | take 25",
        days,
    )


# --- Schemas ----------------------------------------------------------------

def _schema(name, desc):
    return {
        "type": "function",
        "function": {
            "name": name, "description": desc,
            "parameters": {
                "type": "object", "additionalProperties": False,
                "required": ["account"],
                "properties": {
                    "account": {"type": "string", "description": "UPN or account name."},
                    "days": {"type": "integer", "minimum": 1, "maximum": 30},
                },
            },
        },
    }


PROFILE_SCHEMA = _schema("get_identity_profile",
    "Privilege, roles, risk state and enablement for an account.")
PATTERNS_SCHEMA = _schema("get_signin_patterns",
    "Sign-in behaviour: volume, failures, countries, apps, risky sign-ins, MFA.")
FAILSUCCESS_SCHEMA = _schema("get_failed_then_success",
    "Failed sign-ins followed by success from the same IP — brute-force/spray success signature.")
RISKY_SCHEMA = _schema("get_risky_signins",
    "Individual medium/high risk sign-in events with detail, for citation.")
AUDIT_SCHEMA = _schema("get_directory_changes",
    "Recent directory changes on the account: role adds, MFA/password changes — post-compromise persistence.")
