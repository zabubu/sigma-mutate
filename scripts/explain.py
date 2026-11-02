"""Explain why a rule could not be turned into an event (or how it was).

Prints: the selections chosen to be true, the candidate event, and the truth value of
every selection and of the whole condition on that event.

Usage:
    py scripts\\explain.py ..\\sigma\\rules\\windows\\process_creation\\some_rule.yml
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml  # noqa: E402

from sigma_mutate.matcher import _selection_matches, eval_condition  # noqa: E402
from sigma_mutate.synth import SynthError, satisfying_selections, synthesize  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        rule = next(d for d in yaml.safe_load_all(f) if isinstance(d, dict) and "detection" in d)
    det = rule["detection"]
    print(f"Rule: {rule.get('title')}")
    print(f"Condition: {det['condition']}\n")
    for name, sel in det.items():
        if name not in ("condition", "timeframe"):
            print(f"[{name}]")
            print(yaml.safe_dump(sel, default_flow_style=False, allow_unicode=True).rstrip(), "\n")

    try:
        chosen = satisfying_selections(det)
        print(f"Selections chosen to be true: {chosen}")
        event = synthesize(rule, verify=False)
    except (SynthError, NotImplementedError) as e:
        print(f"Cannot build an event: {e}")
        return 1
    print("Candidate event:")
    for k, v in event.items():
        print(f"  {k} = {v!r}")
    truth = {}
    for name, sel in det.items():
        if name in ("condition", "timeframe"):
            continue
        try:
            truth[name] = _selection_matches(sel, event)
        except NotImplementedError as e:
            truth[name] = f"unsupported ({e})"
        print(f"  [{name}] -> {truth[name]}")
    cond = det["condition"]
    try:
        result = any(eval_condition(c, truth) for c in (cond if isinstance(cond, list) else [cond]))
        print(f"Condition on candidate event: {result}")
    except Exception as e:
        print(f"Condition could not be evaluated: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
