from envelope import run_kql

q = """
SecurityAlert
| where isnotempty(Entities) and Entities != '[]'
| summarize AlertsWithEntities = count() by ProductName
"""
for row in run_kql(q, days=90):
    print(row)

q2 = """
SecurityIncident
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertId = todynamic(AlertIds) to typeof(string)
| join kind=inner (
    SecurityAlert
    | where isnotempty(Entities) and Entities != '[]'
    | project SystemAlertId
  ) on $left.AlertId == $right.SystemAlertId
| summarize Alerts = count() by IncidentNumber, Title
| order by Alerts desc
| take 10
"""
for row in run_kql(q2, days=90):
    print(row)