"""Run sigma-mutate over a directory of Sigma rules (e.g. a SigmaHQ clone).

For each rule: synthesize a true-positive event, mutate its CommandLine, score the rule.
Rules the MVP cannot handle are counted with a reason (that list is our feature backlog).

Usage:
    py scripts\\corpus.py C:\\path\\to\\sigma\\rules\\windows\\process_creation --csv results.csv
    py scripts\\corpus.py <dir> --limit 50 --verify-rsigma
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml  # noqa: E402

from sigma_mutate.reference import rsigma_matches  # noqa: E402
from sigma_mutate.scoring import score_rule  # noqa: E402
from sigma_mutate.synth import SynthError, synthesize  # noqa: E402


def load_rule(path: str):
    with open(path, encoding="utf-8") as f:
        for doc in yaml.safe_load_all(f):
            if isinstance(doc, dict) and "detection" in doc:
                return doc
    return None


def analyse(path: str, args) -> dict:
    row = {"path": path, "title": "", "status": "", "reason": "", "total": 0, "detected": 0, "score": ""}
    try:
        rule = load_rule(path)
    except Exception as e:  # malformed YAML
        row.update(status="load_error", reason=str(e)[:120])
        return row
    if rule is None:
        row.update(status="skipped", reason="no detection block")
        return row
    row["title"] = rule.get("title", "")
    ls = rule.get("logsource") or {}
    if args.category and ls.get("category") != args.category:
        row.update(status="skipped", reason=f"category {ls.get('category')}")
        return row
    try:
        event = synthesize(rule)
        if "CommandLine" not in event:
            row.update(status="no_commandline", reason="rule does not constrain CommandLine")
            return row
        if args.verify_rsigma and not rsigma_matches(args.rsigma, path, event):
            row.update(status="rsigma_disagrees", reason="rsigma does not match the synthesized event")
            return row
        report = score_rule(rule, event)
    except SynthError as e:
        row.update(status="unsupported", reason=str(e)[:120])
        return row
    except NotImplementedError as e:
        row.update(status="unsupported", reason=str(e)[:120])
        return row
    except Exception as e:
        row.update(status="error", reason=f"{type(e).__name__}: {e}"[:120])
        return row
    if report.total == 0:
        row.update(status="no_mutations", reason="no mutation applicable")
        return row
    row.update(status="scored", total=report.total, detected=report.detected, score=round(report.score, 3))
    return row


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("directory")
    p.add_argument("--category", default="process_creation", help="logsource category filter ('' = all)")
    p.add_argument("--limit", type=int, default=0, help="analyse only the first N rules")
    p.add_argument("--csv", default="results.csv")
    p.add_argument("--verify-rsigma", action="store_true", help="check synthesized events with rsigma (slow)")
    p.add_argument("--rsigma", default=shutil.which("rsigma") or "rsigma")
    args = p.parse_args()

    paths = sorted(os.path.join(d, f) for d, _, fs in os.walk(args.directory)
                   for f in fs if f.endswith((".yml", ".yaml")))
    if args.limit:
        paths = paths[: args.limit]

    rows = [analyse(path, args) for path in paths]
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["path"])
        w.writeheader()
        w.writerows(rows)

    counts = collections.Counter(r["status"] for r in rows)
    print(f"{len(rows)} files analysed\n")
    for status, n in counts.most_common():
        print(f"  {status:18} {n}")
    reasons = collections.Counter(r["reason"] for r in rows if r["status"] == "unsupported")
    if reasons:
        print("\nTop reasons for 'unsupported' (our feature backlog):")
        for reason, n in reasons.most_common(8):
            print(f"  {n:4}  {reason}")
    scored = [r for r in rows if r["status"] == "scored"]
    if scored:
        mean = sum(r["score"] for r in scored) / len(scored)
        robust = sum(r["score"] == 1 for r in scored)
        print(f"\nScored rules: {len(scored)} | mean score {mean:.2f} | fully robust: {robust} | with evasions: {len(scored) - robust}")
        print("\nWeakest rules:")
        for r in sorted(scored, key=lambda r: r["score"])[:10]:
            print(f"  {r['score']:.2f}  {r['title']}")
    print(f"\nDetails written to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
