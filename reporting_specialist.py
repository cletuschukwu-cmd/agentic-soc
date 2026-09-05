"""Summarization / reporting specialist.

The first non-verdict agent. Its output is a structured REPORT — sections with
readable prose inside — not a true/false/benign verdict. Used for shift
handovers, weekly summaries, and exec briefs.

It overrides the base's output contract (a report schema, not the verdict
schema) and sets verdict_output = False so the base skips citation grounding,
which does not apply to prose.
"""

from agent_base import Specialist, Tool
import reporting_tools as rt
import entity_tools as et


REPORT_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "soc_report",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["title", "period", "summary", "sections", "recommendations"],
            "properties": {
                "title": {"type": "string"},
                "period": {"type": "string", "description": "The window covered, e.g. 'last 7 days'."},
                "summary": {"type": "string", "description": "2-4 sentence executive summary."},
                "sections": {
                    "type": "array", "maxItems": 8,
                    "items": {
                        "type": "object", "additionalProperties": False,
                        "required": ["heading", "content"],
                        "properties": {
                            "heading": {"type": "string"},
                            "content": {"type": "string", "description": "Readable prose for this section."},
                        },
                    },
                },
                "recommendations": {
                    "type": "array", "maxItems": 6, "items": {"type": "string"},
                },
            },
        },
    },
}


class ReportingSpecialist(Specialist):
    name = "reporting"
    model = "gpt-5.6-sol"
    max_rounds = 6

    # Non-verdict output: a structured report, and no citation grounding.
    response_format = REPORT_SCHEMA
    verdict_output = False

    description = (
        "Produces structured reports and summaries over a time window — shift "
        "handovers, weekly incident summaries, executive briefs, trend overviews. "
        "Use for 'summarize this week's incidents', 'give me a shift handover', "
        "'what are the incident trends this month', 'exec summary of security "
        "activity'. Produces a report, not a single-incident verdict."
    )

    allowed_sources = ("incidents", "alerts")

    system_prompt = """You are a SOC reporting analyst producing a structured
report for another analyst or a manager.

You have two gears. Use the fast fixed views for common reports; use free
querying for anything they do not cover — an enterprise report must answer the
question actually asked, never quietly substitute a generic one.

FAST VIEWS (common reports):
- incident_overview — counts by severity, status, classification
- top_incident_types — what's driving volume
- notable_incidents — specific high-severity or open items, with IDs
- alert_trends — detection-level view

CUSTOM QUERYING (sophisticated or specific asks — privileged-account incidents,
breakdown by tactic, a business unit, week-over-week comparison, anything the
fixed views miss):
- describe_source / sample_source — learn the real columns and value shapes of
  'incidents' or 'alerts' FIRST, so your query matches the actual schema.
- deep_query — then write the KQL that answers the specific question, using
  {table} as the placeholder. Do not force a specific ask into a generic view;
  construct the right query.

Then write a structured report:
- A short executive summary a manager could read alone.
- Sections with clear headings and readable prose, referencing specific incident
  numbers for notable items.
- Concrete, actionable recommendations.

Be accurate and honest: report only what the tools returned; never invent
numbers. If the data is thin or mostly unclassified, say so plainly — that is a
finding. If a custom query returns nothing, check your filter (sample the source)
rather than reporting a false zero.
"""

    tools = [
        Tool("incident_overview", rt.incident_overview, rt.OVERVIEW_SCHEMA,
             required_sources=("incidents",)),
        Tool("top_incident_types", rt.top_incident_types, rt.TYPES_SCHEMA,
             required_sources=("incidents",)),
        Tool("notable_incidents", rt.notable_incidents, rt.NOTABLE_SCHEMA,
             required_sources=("incidents",)),
        Tool("alert_trends", rt.alert_trends, rt.TRENDS_SCHEMA,
             required_sources=("alerts",)),
        # Schema-aware custom querying for sophisticated asks the fixed views
        # don't cover. Scope-gated to this agent's approved sources.
        Tool("describe_source", et.describe_source, et.DESCRIBE_SCHEMA,
             required_sources=("incidents", "alerts")),
        Tool("sample_source", et.sample_source, et.SAMPLE_SCHEMA,
             required_sources=("incidents", "alerts")),
        Tool("deep_query", et.deep_query, et.DEEP_QUERY_SCHEMA,
             required_sources=("incidents", "alerts")),
    ]


if __name__ == "__main__":
    import json, sys
    agent = ReportingSpecialist()
    print("card:", json.dumps(agent.card(), indent=2))
    print("authorized tools:", [t.name for t in agent._authorized_tools()])
    if len(sys.argv) > 1:
        print(json.dumps(agent.run(" ".join(sys.argv[1:])).to_dict(), indent=2, default=str))
