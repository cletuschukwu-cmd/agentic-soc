import sys
from envelope import run_kql

hours = int(sys.argv[1]) if len(sys.argv) > 1 else 2
q = f"""
SecurityIncident
| where TimeGenerated > ago({hours}h)
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, CreatedTime
| order by CreatedTime desc
"""
for row in run_kql(q, days=1):
    print(f"{row['IncidentNumber']}  {row['Severity']:<8} {row['Status']:<12} {row['Title']}")