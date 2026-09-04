from envelope import run_kql

# Which of the tables an entity investigation would touch actually have data?
candidates = [
    "DeviceNetworkEvents", "DeviceProcessEvents", "DeviceFileEvents",
    "DeviceLogonEvents", "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "IdentityInfo", "DeviceInfo", "ThreatIntelligenceIndicator",
    "CommonSecurityLog", "DeviceEvents",
]

for t in candidates:
    try:
        rows = run_kql(f"{t} | where TimeGenerated > ago(30d) | count", days=30)
        n = rows[0].get("Count", 0) if rows else 0
        print(f"{t:<38} {n}")
    except Exception as e:
        print(f"{t:<38} MISSING ({str(e)[:50]})")