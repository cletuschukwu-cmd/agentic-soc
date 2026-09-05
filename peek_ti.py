from envelope import run_kql
# Discover the real columns of ThreatIntelIndicators so the tool matches the schema
rows = run_kql("ThreatIntelIndicators | getschema | project ColumnName, ColumnType", days=1)
for r in rows:
    print(r["ColumnName"], "|", r["ColumnType"])
