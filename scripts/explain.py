"""Explain why a rule could not be turned into an event (or how it was).

Prints: the selections chosen to be true, the candidate event, and the truth value of
every selection and of the whole condition on that event.

Usage:
    py scripts\\explain.py ..\\sigma\\rules\\windows\\process_creation\\some_rule.yml
    py scripts\\explain.py whoami_output          # part of a file name is enough
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import yaml  # noqa: E402

from sigma_mutate.matcher import _selection_matches, eval_condition  # noqa: E402
from sigma_mutate.scoring import score_rule  # noqa: E402
from sigma_mutate.synth import SynthError, satisfying_selections, synthesize_ex  # noqa: E402


def resolve(arg: str) -> str | None:
    """A path, or a part of a file name searched in the SigmaHQ folder (env SIGMA_RULES to override)."""
    if os.path.isfile(arg):
        return arg
    root = os.environ.get("SIGMA_RULES") or os.path.join(
        os.path.dirname(__file__), "..", "..", "sigma", "rules", "windows", "process_creation")
    hits = sorted(f for f in os.listdir(root) if arg.lower() in f.lower() and f.endswith((".yml", ".yaml"))) \
        if os.path.isdir(root) else []
    if len(hits) == 1:
        return os.path.join(root, hits[0])
    if hits:
        print(f"Several files match '{arg}':")
        for h in hits[:15]:
            print(f"  {h}")
    else:
        print(f"No file found for '{arg}' (looked in {os.path.abspath(root)}).")
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = resolve(sys.argv[1])
    if not path:
        return 2
    with open(path, encoding="utf-8") as f:
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
        event, _ = synthesize_ex(rule, verify=False)
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
    if result and "CommandLine" in event:
        print("\nVariants of CommandLine (argv-equivalent first):")
        report = score_rule(rule, event, assumptions=("argv", "cmd.exe", "program"))
        for r in sorted(report.results, key=lambda r: r.mutation.assumption != "argv"):
            m = r.mutation
            print(f"  {'detected' if r.detected else 'EVADED  '} [{m.assumption}] {m.mutator} {m.label}\n"
                  f"           {m.value!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
