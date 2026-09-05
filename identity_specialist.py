"""Identity-compromise specialist.

Answers "is this account compromised" by reasoning over privilege, sign-in
behaviour, risk signals, brute-force/spray signatures, and post-compromise
directory changes. Other specialists consult this one when they hit a suspicious
account (via orchestrator.consult).
"""

from agent_base import Specialist, Tool
import identity_tools as it


class IdentitySpecialist(Specialist):
    name = "identity_investigator"
    model = "gpt-5.6-sol"  # heavy reasoning
    max_rounds = 8

    description = (
        "Investigates whether a user account is compromised. Reasons over "
        "privilege and risk state, sign-in patterns (locations, failures, "
        "impossible travel), brute-force/password-spray success signatures, "
        "risky sign-ins, and post-compromise directory changes (role adds, MFA "
        "resets). Use for questions like 'is steveadmin compromised', 'check "
        "this account for suspicious sign-ins', 'has this user been breached'."
    )

    allowed_sources = ("identity_info", "signins", "noninteractive_signins", "audit")

    system_prompt = """You are a senior identity/SOC analyst determining whether an
account is compromised.

Investigate efficiently, hypothesis-first:
1. Start with get_identity_profile — privilege and risk state frame everything.
   A compromised low-privilege account and a compromised Global Admin are very
   different severities.
2. get_signin_patterns for the behavioural baseline — where, how often, failures,
   risky sign-ins, MFA.
3. If anything looks off, drill: get_failed_then_success (spray/brute-force
   success), get_risky_signins (individual risk events to cite),
   get_directory_changes (persistence moves after compromise).

Reason like an analyst:
- Impossible travel, a spray-then-success, a risky sign-in that succeeded
  without MFA, or a role/MFA change right after an anomalous sign-in are strong
  compromise indicators.
- Privilege amplifies severity. Flag privileged accounts explicitly.
- Absence of risky sign-ins is NOT proof of safety — say so if telemetry is thin.

Conclude with a verdict:
- Cite evidence you retrieved; every key_evidence item carries a source and an
  identifier that resolves. Never invent identifiers.
- insufficient_evidence when the data genuinely doesn't support a conclusion.
- Missing a real compromise is far worse than a false alarm. When torn, escalate.
- Keep reasoning under 120 words.
"""

    tools = [
        Tool("get_identity_profile", it.get_identity_profile, it.PROFILE_SCHEMA,
             required_sources=("identity_info",)),
        Tool("get_signin_patterns", it.get_signin_patterns, it.PATTERNS_SCHEMA,
             required_sources=("signins",)),
        Tool("get_failed_then_success", it.get_failed_then_success, it.FAILSUCCESS_SCHEMA,
             required_sources=("signins",)),
        Tool("get_risky_signins", it.get_risky_signins, it.RISKY_SCHEMA,
             required_sources=("signins",)),
        Tool("get_directory_changes", it.get_directory_changes, it.AUDIT_SCHEMA,
             required_sources=("audit",)),
    ]


if __name__ == "__main__":
    import json, sys
    agent = IdentitySpecialist()
    print("card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])
    if len(sys.argv) > 1:
        print(json.dumps(agent.run(" ".join(sys.argv[1:])).to_dict(), indent=2, default=str))
