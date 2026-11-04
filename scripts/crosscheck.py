"""Compare our matcher with rsigma on one rule: the event, a few probes and every variant.

Usage:
    py scripts\\crosscheck.py examples\\certutil_rule.yml examples\\certutil_event.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml  # noqa: E402

from sigma_mutate.matcher import matches  # noqa: E402
from sigma_mutate.mutators import generate  # noqa: E402
from sigma_mutate.reference import rsigma_matches  # noqa: E402


def probes(event: dict, field: str) -> list[tuple[str, dict]]:
    cmd = str(event[field])
    without = {k: v for k, v in event.items() if k != field}
    return [
        ("original event", event),
        ("command line upper-cased", {**event, field: cmd.upper()}),
        ("command line lower-cased", {**event, field: cmd.lower()}),
        (f"field '{field}' removed", without),
    ]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("rule")
    p.add_argument("event")
    p.add_argument("--field", default="CommandLine")
    p.add_argument("--rsigma", default=shutil.which("rsigma") or "rsigma")
    p.add_argument("--assumptions", default="argv,cmd.exe,program",
                   help="mutations to include (engines are compared, not validity)")
    a = p.parse_args()

    with open(a.rule, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(a.event, encoding="utf-8") as f:
        event = json.load(f)

    cases = probes(event, a.field)
    for m in generate(str(event[a.field]), tuple(a.assumptions.split(","))):
        cases.append((f"{m.mutator} [{m.assumption}] {m.label}", {**event, a.field: m.value}))

    disagreements = 0
    print(f"Rule: {rule.get('title', '<untitled>')}  |  {len(cases)} cases\n")
    for label, ev in cases:
        ours = matches(rule, ev)
        ref = rsigma_matches(a.rsigma, a.rule, ev)
        ok = ours == ref
        disagreements += not ok
        flag = "ok      " if ok else "DIFFERS "
        print(f"{flag} ours={str(ours):5} rsigma={str(ref):5}  {label}")
        if not ok:
            print(f"           event {a.field}: {ev.get(a.field)!r}")

    print(f"\n{len(cases) - disagreements}/{len(cases)} agree")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
