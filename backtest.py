"""Backtest harness.

This is the deliverable. The agent is the thing you demo; the harness is the
thing that makes the demo credible and the thing that survives into
production. It is customer code by design, so it runs in either cloud and
does not depend on a managed evaluations service.

The eval set is drawn from incidents your analysts already closed. Dwell-time
bounds drop bulk end-of-shift closures, which produce garbage labels.

Usage:
    python backtest.py --limit 60 --out results.json
    python backtest.py --report results.json
"""

import argparse
import json
import random
from collections import Counter, defaultdict

import config
import contracts
from envelope import build_envelope, run_kql

EVAL_SET_QUERY = """
SecurityIncident
| where Status == 'Closed' and isnotempty(Classification)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend DwellMin = datetime_diff('minute', ClosedTime, CreatedTime)
| where DwellMin between (3 .. 2880)
| project IncidentNumber, Title, Severity, Classification, DwellMin
"""

INVENTORY_QUERY = """
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend DwellMin = datetime_diff('minute', coalesce(ClosedTime, now()), CreatedTime)
| summarize Incidents = count(),
            DistinctTitles = dcount(Title),
            Closed = countif(Status == 'Closed'),
            Active = countif(Status != 'Closed'),
            Unclassified = countif(isempty(Classification)),
            Undetermined = countif(Classification == 'Undetermined'),
            TruePositive = countif(Classification == 'TruePositive'),
            BenignPositive = countif(Classification == 'BenignPositive'),
            FalsePositive = countif(Classification == 'FalsePositive'),
            InstantClose = countif(Status == 'Closed' and DwellMin < 3),
            Earliest = min(CreatedTime),
            Latest = max(CreatedTime)
"""

ALERT_INVENTORY_QUERY = """
SecurityAlert
| summarize Alerts = count(),
            DistinctAlertNames = dcount(AlertName),
            Products = make_set(ProductName, 15),
            Earliest = min(TimeGenerated),
            Latest = max(TimeGenerated)
"""

BASELINE_QUERY = """
SecurityIncident
| where Status == 'Closed'
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend DwellMin = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize Total = count(),
            FP = countif(Classification == 'FalsePositive'),
            BP = countif(Classification == 'BenignPositive'),
            TP = countif(Classification == 'TruePositive'),
            Undetermined = countif(Classification == 'Undetermined'),
            Unclassified = countif(isempty(Classification)),
            Usable = countif(Classification in ('TruePositive','BenignPositive','FalsePositive')
                             and DwellMin between (3 .. 2880)),
            MedianDwellMin = percentile(DwellMin, 50)
  by Title
| extend FPRate = iff(Total > 0, round(100.0 * FP / Total, 1), 0.0)
| order by Total desc
"""


def inventory(days: int = None) -> dict:
    """What is actually in this workspace. Run this before anything else."""
    days = days or config.HISTORY_DAYS
    inc = run_kql(INVENTORY_QUERY, days=days)
    alerts = run_kql(ALERT_INVENTORY_QUERY, days=days)
    summary = inc[0] if inc else {}
    usable = (
        summary.get("TruePositive", 0)
        + summary.get("BenignPositive", 0)
        + summary.get("FalsePositive", 0)
    )
    return {
        "window_days": days,
        "incidents": summary,
        "alerts": alerts[0] if alerts else {},
        "usable_labels": usable,
        "verdict": (
            "sufficient — proceed to backtest"
            if usable >= 30
            else "INSUFFICIENT — seed the lab before backtesting"
        ),
    }


def baseline(days: int = None) -> list[dict]:
    """Rule-level disposition. No AI involved; this is the day-one deliverable."""
    return run_kql(BASELINE_QUERY, days=days or config.HISTORY_DAYS)


def load_eval_set(limit: int, days: int = None, seed: int = 7) -> list[dict]:
    rows = run_kql(EVAL_SET_QUERY, days=days or config.HISTORY_DAYS)
    by_label = defaultdict(list)
    for r in rows:
        by_label[r["Classification"]].append(r)

    rng = random.Random(seed)
    per_label = max(1, limit // max(1, len(by_label)))
    sample = []
    for label, items in by_label.items():
        rng.shuffle(items)
        sample.extend(items[:per_label])
    rng.shuffle(sample)
    return sample[:limit]


def score(records: list[dict]) -> dict:
    scored = [r for r in records if r["status"] == "ok"]
    agree = sum(int(r["expected"] == r["predicted"]) for r in scored)

    tp = [r for r in scored if r["expected"] == "likely_true_positive"]
    tp_caught = sum(
        int(r["predicted"] == "likely_true_positive" or r["action"] in ("investigate", "escalate"))
        for r in tp
    )

    grounded = [r["groundedness"] for r in scored if r["citations_total"]]
    latencies = sorted(r["latency"] for r in scored)

    return {
        "evaluated": len(records),
        "completed": len(scored),
        "unavailable": len(records) - len(scored),
        "agreement_rate": round(agree / len(scored), 3) if scored else None,
        "true_positive_recall": round(tp_caught / len(tp), 3) if tp else None,
        "true_positive_n": len(tp),
        "mean_groundedness": round(sum(grounded) / len(grounded), 3) if grounded else None,
        "flagged_citations": sum(int(r["flagged"]) for r in scored),
        "insufficient_evidence_rate": round(
            sum(int(r["predicted"] == "insufficient_evidence") for r in scored) / len(scored), 3
        )
        if scored
        else None,
        "median_latency_seconds": latencies[len(latencies) // 2] if latencies else None,
        "confusion": Counter(f"{r['expected']} -> {r['predicted']}" for r in scored),
    }


def run(limit: int, out: str) -> None:
    # Imported here, not at module scope, so --baseline and --report work
    # without the openai package installed. Day one needs no AI.
    from agent import triage

    sample = load_eval_set(limit)
    print(f"eval set: {len(sample)} incidents")
    if len(sample) < 30:
        print(
            "WARNING: fewer than 30 labelled incidents. Seed the lab with the "
            "Sentinel Training Lab solution or Defender XDR attack simulation, "
            "and state in the demo that the eval set is manufactured."
        )

    records = []
    for i, row in enumerate(sample, 1):
        number = row["IncidentNumber"]
        expected = contracts.LABEL_MAP.get(row["Classification"])
        try:
            env = build_envelope(number)
            result = triage(env)
        except Exception as exc:  # noqa: BLE001
            result = {"status": "unavailable", "reason": str(exc)}

        rec = {
            "incident_number": number,
            "title": row["Title"],
            "expected": expected,
            "status": result["status"],
        }
        if result["status"] == "ok":
            v, g = result["verdict"], result["grounding"]
            rec.update(
                predicted=v["verdict"],
                confidence=v["confidence"],
                action=v["recommended_action"],
                reasoning=v["reasoning"],
                groundedness=g["groundedness"],
                citations_total=g["citations_total"],
                flagged=g["flagged"],
                latency=result["latency_seconds"],
                unavailable_context=v.get("unavailable_context", []),
            )
            mark = "ok " if rec["expected"] == rec["predicted"] else "DIFF"
        else:
            rec["reason"] = result.get("reason")
            mark = "ERR "
        records.append(rec)
        print(f"[{i}/{len(sample)}] {mark} #{number} {row['Title'][:48]}")

    metrics = score(records)
    metrics["confusion"] = dict(metrics["confusion"])
    with open(out, "w") as fh:
        json.dump({"metrics": metrics, "records": records}, fh, indent=2, default=str)

    print("\n" + json.dumps(metrics, indent=2, default=str))
    disagreements = [
        r for r in records if r["status"] == "ok" and r["expected"] != r["predicted"]
    ]
    print(f"\n{len(disagreements)} disagreements written to {out}.")
    print("Review every one by hand. They are the most valuable output of this run.")


def report(path: str) -> None:
    data = json.load(open(path))
    print(json.dumps(data["metrics"], indent=2))
    print("\n--- disagreements ---")
    for r in data["records"]:
        if r["status"] == "ok" and r["expected"] != r["predicted"]:
            print(f"\n#{r['incident_number']} {r['title']}")
            print(f"  analyst: {r['expected']}   agent: {r['predicted']} ({r['confidence']})")
            print(f"  {r['reasoning']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--report")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--inventory", action="store_true")
    ap.add_argument("--days", type=int, default=None)
    args = ap.parse_args()

    if args.inventory:
        print(json.dumps(inventory(args.days), indent=2, default=str))
    elif args.baseline:
        print(json.dumps(baseline(args.days), indent=2, default=str))
    elif args.report:
        report(args.report)
    else:
        run(args.limit, args.out)
