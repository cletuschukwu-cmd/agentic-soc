"""Specialist evaluation harness.

Grounded is not the same as right. Grounded means every citation resolves.
Right means the verdict matches expert judgment. This harness measures the
second, for any specialist built on the agent base.

It runs a specialist against a set of known-answer cases — entities or
incidents where a human has established the correct verdict — and reports:

  agreement       how often the agent's verdict matches the human label
  tp_recall       of the cases that are truly positive, how many the agent
                  caught (the number that matters most; a missed intrusion is
                  far worse than a false alarm)
  groundedness    mean fraction of cited identifiers that resolve
  calibration     do verdicts at confidence ~0.8 turn out right ~80% of the
                  time — is the confidence honest

Cases live in eval/<specialist>.jsonl, one JSON object per line:
  {"task": "what do we know about host knightsdc01",
   "expected": "likely_benign",
   "note": "gc_worker.exe is authorized Azure Guest Configuration"}

Usage:
  python eval_harness.py entity_investigator
  python eval_harness.py incident_triage --out triage_eval.json
  python eval_harness.py --template entity_investigator   # write a starter file
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from customer import customer
from orchestrator import registry

EVAL_DIR = Path(os.environ.get("AISOC_EVAL_DIR", "eval"))

# Verdicts collapse to a positive/negative axis for recall on real threats.
_POSITIVE = {"likely_true_positive"}
_NEGATIVE = {"likely_benign", "likely_false_positive"}


def _cases_path(specialist: str) -> Path:
    return EVAL_DIR / f"{specialist}.jsonl"


def load_cases(specialist: str) -> list[dict]:
    path = _cases_path(specialist)
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _calibration(records: list[dict]) -> list[dict]:
    """Bucket verdicts by confidence and report hit-rate per bucket.
    A well-calibrated agent's 0.8 bucket is right about 80% of the time."""
    buckets = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in records:
        if r["status"] != "ok":
            continue
        c = r.get("confidence")
        if c is None:
            continue
        b = f"{int(c * 10) * 10}-{int(c * 10) * 10 + 10}%"
        buckets[b]["n"] += 1
        buckets[b]["correct"] += int(r["expected"] == r["predicted"])
    out = []
    for b in sorted(buckets):
        d = buckets[b]
        out.append({"confidence_bucket": b, "n": d["n"],
                    "accuracy": round(d["correct"] / d["n"], 2) if d["n"] else None})
    return out


def evaluate(specialist_name: str, out_path: str | None = None) -> dict:
    agents = registry()
    if specialist_name not in agents:
        return {"error": f"no specialist '{specialist_name}'. "
                         f"available: {list(agents)}"}
    agent = agents[specialist_name]

    cases = load_cases(specialist_name)
    if not cases:
        return {"error": f"no eval cases at {_cases_path(specialist_name)}. "
                         f"Run with --template {specialist_name} to create a starter file."}

    records = []
    for i, case in enumerate(cases, 1):
        expected = case["expected"]
        print(f"[{i}/{len(cases)}] {case['task'][:60]}")
        result = agent.run(case["task"]).to_dict()
        rec = {"task": case["task"], "expected": expected, "status": result["status"]}
        if result["status"] == "ok":
            v, g = result["verdict"], result.get("grounding") or {}
            rec.update(predicted=v["verdict"], confidence=v["confidence"],
                       groundedness=g.get("groundedness"),
                       latency=result.get("latency_seconds"))
            mark = "ok " if expected == v["verdict"] else "DIFF"
        else:
            rec["reason"] = result.get("reason")
            mark = "ERR"
        records.append(rec)
        print(f"        {mark}  expected={expected}  "
              f"got={rec.get('predicted', result['status'])}")

    ok = [r for r in records if r["status"] == "ok"]
    agree = sum(int(r["expected"] == r["predicted"]) for r in ok)
    truly_pos = [r for r in ok if r["expected"] in _POSITIVE]
    caught = sum(int(r["predicted"] in _POSITIVE) for r in truly_pos)
    grounded = [r["groundedness"] for r in ok if r.get("groundedness") is not None]

    metrics = {
        "specialist": specialist_name,
        "customer": customer().name,
        "cases": len(records),
        "completed": len(ok),
        "errored": len(records) - len(ok),
        "agreement": round(agree / len(ok), 2) if ok else None,
        "tp_recall": round(caught / len(truly_pos), 2) if truly_pos else None,
        "tp_cases": len(truly_pos),
        "mean_groundedness": round(sum(grounded) / len(grounded), 2) if grounded else None,
        "calibration": _calibration(records),
        "confusion": dict(Counter(f"{r['expected']}->{r['predicted']}" for r in ok)),
    }

    print("\n" + json.dumps(metrics, indent=2))
    disagree = [r for r in ok if r["expected"] != r["predicted"]]
    if disagree:
        print(f"\n{len(disagree)} disagreements — review each:")
        for r in disagree:
            print(f"  {r['task'][:55]}  expected={r['expected']} got={r['predicted']} "
                  f"(conf {r['confidence']})")

    if out_path:
        Path(out_path).write_text(json.dumps(
            {"metrics": metrics, "records": records}, indent=2, default=str))
        print(f"\nwritten to {out_path}")
    return metrics


def write_template(specialist_name: str) -> None:
    EVAL_DIR.mkdir(exist_ok=True)
    path = _cases_path(specialist_name)
    if path.exists():
        print(f"{path} already exists — not overwriting")
        return
    examples = [
        {"task": "what do we know about host knightsdc01",
         "expected": "likely_benign",
         "note": "REPLACE with your real known-answer cases. gc_worker.exe was "
                 "authorized Azure Guest Configuration in the lab."},
        {"task": "is 13.82.149.123 malicious",
         "expected": "likely_benign",
         "note": "REPLACE. Example of a benign external Microsoft/Azure IP."},
    ]
    path.write_text("\n".join(json.dumps(e) for e in examples) + "\n")
    print(f"wrote starter cases to {path}")
    print("Edit it: set 'expected' to the correct verdict you (the analyst) "
          "establish for each task, add more cases, then run the eval.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("specialist", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--template", metavar="SPECIALIST")
    args = ap.parse_args()

    if args.template:
        write_template(args.template)
    elif args.specialist:
        result = evaluate(args.specialist, args.out)
        if "error" in result:
            print(result["error"])
    else:
        print("specialists:", list(registry()))
        print("usage: python eval_harness.py <specialist> [--out file] | "
              "--template <specialist>")
