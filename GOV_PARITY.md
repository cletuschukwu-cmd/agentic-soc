# Azure Government Parity Tracker

Every Azure feature, service, and model this platform depends on, with its
Azure Government availability status. The rule for this project: **we build in
Azure Commercial, but nothing gets adopted without checking it here first.** If
a dependency is not available (or not authorized) in Azure Government, we either
find a Gov-available equivalent or explicitly record it as a Gov gap to resolve
before a Gov deployment.

Status:
- **GA-both** — generally available in Commercial AND Azure Government
- **Gov-verified** — confirmed present in the customer's Gov tenant (stronger
  than docs, which have been wrong before)
- **Commercial-only** — not in Gov; needs an equivalent or is a blocker
- **Check** — not yet verified for Gov; verify before relying on it
- **Preview-Gov** — in Gov but preview (excluded from regulated production)

> Note: Microsoft docs have repeatedly understated Gov availability in this
> project (models, agent tools). Prefer verifying in the actual Gov tenant over
> trusting documentation. "Gov-verified" means we saw it in the tenant.

---

## Core compute & app

| Dependency | Purpose | Gov status | Notes |
|---|---|---|---|
| Azure Container Apps / Functions | Host the API + agents | Check | Verify the specific host chosen is in Gov + in the ATO scope. Containers are the portability play. |
| Azure Key Vault | Secret storage | GA-both | Vault URI suffix differs (vault.usgovcloudapi.net). Handled in kv_secrets.py. |
| Managed identity | App identity, no secrets | GA-both | The deploy-time identity model; avoids stored secrets. |
| Entra ID (OIDC) | User authentication | GA-both | Gov uses login.microsoftonline.us. auth.py seam handles it. |

## AI / models

| Dependency | Purpose | Gov status | Notes |
|---|---|---|---|
| Azure OpenAI | Model inference | GA-both | Gov endpoint services.ai.azure.us. |
| gpt-5.6-sol (specialists) | Reasoning | Gov-verified | Seen in Gov model list (DataZoneStandard). Confirm SKU/region per deployment. |
| gpt-4.1-mini (router, planned) | Cheap routing | Check | Confirm deployed in Gov before relying on the cheap-router optimization. |
| Foundry Agent Service | (NOT used) | n/a | Deliberately avoided — code-orchestrated instead, for portability. Foundry portal/playground usable; runtime is our code. |

## Data sources

| Dependency | Purpose | Gov status | Notes |
|---|---|---|---|
| Log Analytics query API | KQL over Sentinel/Defender tables | GA-both | Gov endpoint api.loganalytics.us. config/customer.py handles it. |
| Microsoft Sentinel | Incidents, alerts | GA-both | Some newer Sentinel features lag in Gov — verify per feature. |
| Defender XDR tables | Endpoint/network telemetry | GA-both | Advanced-hunting cross-table joins historically limited in GCC Moderate — verify for target env. |
| Defender API (Ti.Read.All) | network_indicators (rest_api) | Check | Gov host api-gov.securitycenter.microsoft.us. defender_api.py already cloud-aware; verify app-reg + consent works in Gov tenant. |
| ThreatIntelIndicators table | threat_intel source | GA-both | KQL table; present where TI feeds are configured. |

## Governance / boundary rules (enforced in code)

| Rule | Where | Notes |
|---|---|---|
| No live external API in Gov | sources.py (_effective_mode) | Gov forces rest_api sources to ingested. Defender API is Microsoft's own boundary, so it's the clean case; third-party APIs (GTI, VirusTotal) must be ingested in Gov. |
| Secrets only in Key Vault | kv_secrets.py | Never in code/repo/env. |
| Reject-by-default auth | auth.py | Holds in every mode. |

## Known Gov gaps / to verify before Gov deployment

1. **Confirm the chosen container host** (Container Apps vs Functions) is GA in
   Gov and inside the customer's authorization boundary.
2. **Verify gpt-4.1-mini** (or chosen cheap router model) is deployable in Gov,
   or the router falls back to the specialist model (works, just not as cheap).
3. **Verify the Defender app registration + Ti.Read.All admin consent** flow
   works in the Gov tenant (the commercial one had CLI/MFA friction; Gov may too).
4. **Purview / data-security sources** (future data-security specialist): confirm
   scanner + classification availability in Gov before building that specialist.
5. **External threat-intel APIs** (GTI, VirusTotal — future): must be INGESTED in
   Gov, not live-called. Registry already enforces this; the ingestion pipeline
   is the work.

## How to use this file

When adopting any new Azure capability during the cloud build:
1. Add a row here with its purpose.
2. Set status — verify in the Gov tenant where possible, don't trust docs alone.
3. If Commercial-only, find an equivalent or log it as a gap above.
4. Update on every new dependency. This file is the Gov-readiness checklist.
