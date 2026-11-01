from __future__ import annotations

import argparse
import json
import sys

import yaml

from .scoring import BaselineError, score_rule


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigma-mutate", description="Mutation testing for a Sigma rule.")
    p.add_argument("rule", help="Sigma rule (YAML)")
    p.add_argument("event", help="a true-positive event (JSON object)")
    p.add_argument("--field", default="CommandLine", help="event field to mutate")
    p.add_argument("--assumptions", default="argv", help="comma list: argv,cmd.exe,program")
    p.add_argument("--fail-under", type=float, default=None, help="exit 1 if score is below this")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    a = p.parse_args(argv)

    with open(a.rule, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(a.event, encoding="utf-8") as f:
        event = json.load(f)

    try:
        report = score_rule(rule, event, a.field, tuple(a.assumptions.split(",")))
    except BaselineError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if a.json:
        print(json.dumps({
            "rule": report.title, "total": report.total, "detected": report.detected,
            "score": report.score,
            "evasions": [{"mutator": r.mutation.mutator, "label": r.mutation.label,
                          "assumption": r.mutation.assumption, "value": r.mutation.value}
                         for r in report.evasions],
        }, indent=2))
    else:
        print(f"Rule: {report.title}")
        print(f"Mutations: {report.total} | detected: {report.detected} | score: {report.score:.2f}")
        for r in report.evasions:
            m = r.mutation
            print(f"  EVADED  {m.mutator} [{m.assumption}] {m.label}\n          {m.value}")

    if a.fail_under is not None and report.score < a.fail_under:
        return 1
    return 0
