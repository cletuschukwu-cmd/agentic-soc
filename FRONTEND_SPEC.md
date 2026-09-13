# Frontend Specification

The enterprise web console for the AI SOC platform. Replaces the HTML prototype
with a production React application. Security-first, role-gated, cloud-hosted.

## Architecture

- **Frontend:** React web application (static build), served to the browser.
- **Backend:** FastAPI gateway (existing api.py, evolved) — authenticates the
  user, checks role, forwards to the Foundry orchestrator, streams results,
  audits. Thin and secure; all agent intelligence lives in Foundry.
- **Agent runtime:** the Foundry `soc-orchestrator` agent (routes to the
  entity / identity / triage specialists via A2A). Code orchestrator is shelved
  as the future Gov fallback.
- **Hosting:** both containerized, deployed to Azure Container Apps (scale-to-
  zero, horizontal scale, managed).
- **Auth:** Entra ID / OIDC for users (SSO, MFA, Conditional Access enforced by
  Entra); managed identity for the backend. Two identities: user governs who
  may ask and what they may do; backend identity does the work.
- **Secrets:** Key Vault. No credentials in the browser or the repo.

## Two experiences behind one app, gated by role

### Analyst console (all authenticated users)
- Natural-language investigation chat -> Foundry orchestrator
- Streaming reasoning + rendered verdicts (disposition/confidence/evidence) and
  reports (sections/recommendations)
- Conversation history (return to past investigations)
- Promptbooks: saved, shareable expert investigation prompts
- Role-appropriate views

### Admin surface (lead / admin roles only)
Full admin capabilities, built incrementally in priority order:
1. **Data access governance** — view enumerated tables; approve/revoke which the
   agents may query (discover-then-approve); audited. (Highest priority — the
   security story.)
2. **User & role management** — assign analyst / lead / auditor; control who can
   run vs read-only.
3. **Audit log review** — every investigation (who, what sources, verdict);
   injection-detection events; per-agent accuracy trend.
4. **Customer / connection config** — onboard customers via form (workspace,
   cloud, model, source kinds), not JSON; manage Sentinel/Defender connections
   and their Key Vault secret references.
5. **Agent & model management** — roster, per-agent scope and model, enable/
   disable, cost tuning.
6. **Approval-policy config** — which agent actions auto-approve vs require human
   approval (critical when action agents / closure-reopen arrive).
7. **Promptbook management** — author/publish shared team promptbooks.

## Build approach

- App shell designed with BOTH areas from day one; role-gated navigation.
- Analyst console built first (core product), then admin functions in the
  priority order above, added incrementally.
- Roles come from auth.py capabilities (analyst / lead / auditor) — already
  built; the Entra token's roles claim drives what each user sees.

## Not in v1 (revisit)
- General document upload / personal file workspaces (no clear SOC use yet).
