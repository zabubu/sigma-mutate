"""Run sigma-mutate over a directory of Sigma rules (e.g. a SigmaHQ clone).

For each rule: synthesize a true-positive event, mutate its CommandLine, check which
variants are still detected. Rules the MVP cannot handle are counted with a reason.

Headline metric: among rules with at least one 'argv' mutation (variants equivalent under
standard Windows argument parsing), how many have at least one variant that is NOT detected?

With --verify-rsigma, every event (original + all mutations) is also replayed through rsigma
and any disagreement between the two engines is reported.

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

from sigma_mutate.mutators import TRIVIAL, status_for  # noqa: E402
from sigma_mutate.reference import rsigma_matches_many  # noqa: E402
from sigma_mutate.scoring import score_rule  # noqa: E402
from sigma_mutate.synth import SynthError, field_independent, rule_program, synthesize_ex  # noqa: E402

ALL_ASSUMPTIONS = ("argv", "cmd.exe", "program")
FIELDS = ["path", "title", "status", "reason", "program", "program_status", "other_paths", "mutations_argv", "evaded_argv", "argv_verdict",
          "mutations_all", "evaded_all", "engine_diffs"]


def load_rule(path: str):
    with open(path, encoding="utf-8") as f:
        for doc in yaml.safe_load_all(f):
            if isinstance(doc, dict) and "detection" in doc:
                return doc
    return None


def analyse(path: str, args, diffs: list) -> dict:
    row = dict.fromkeys(FIELDS, "")
    row["path"] = path
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
        event, positive = synthesize_ex(rule)
        if "CommandLine" not in positive:
            row.update(status="no_commandline", reason="rule does not constrain CommandLine")
            return row
        prog = rule_program(rule, event)
        row["program"] = (prog or "(unspecified)").lower()
        row["program_status"] = status_for(prog)
        row["other_paths"] = field_independent(rule, "CommandLine")
        report = score_rule(rule, event, assumptions=ALL_ASSUMPTIONS)
        if report.total == 0:
            row.update(status="no_mutations", reason="no mutation applicable")
            return row
        if args.verify_rsigma:
            events = [event] + [{**event, "CommandLine": r.mutation.value} for r in report.results]
            ref = rsigma_matches_many(args.rsigma, path, events)
            if not ref[0]:
                row.update(status="rsigma_disagrees", reason="rsigma does not match the synthesized event")
                return row
            n = 0
            for r, rv in zip(report.results, ref[1:]):
                if r.detected != rv:
                    n += 1
                    diffs.append((row["title"], f"{r.mutation.mutator} {r.mutation.label}", r.detected, rv, r.mutation.value))
            row["engine_diffs"] = n
    except (SynthError, NotImplementedError) as e:
        row.update(status="unsupported", reason=str(e)[:120])
        return row
    except Exception as e:
        row.update(status="error", reason=f"{type(e).__name__}: {e}"[:120])
        return row

    argv = [r for r in report.results if r.mutation.assumption == "argv"]
    nontrivial = [r for r in argv if r.mutation.mutator not in TRIVIAL]
    evaded_argv = sum(not r.detected for r in argv)
    if evaded_argv:
        verdict = "evadable"
    elif len(nontrivial) >= args.min_variants:
        verdict = "resistant"
    else:
        verdict = "inconclusive"  # too few meaningful variants to claim anything
    row.update(status="scored", mutations_argv=len(argv), evaded_argv=evaded_argv, argv_verdict=verdict,
               mutations_all=report.total, evaded_all=len(report.evasions))
    return row


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("directory")
    p.add_argument("--category", default="process_creation", help="logsource category filter ('' = all)")
    p.add_argument("--limit", type=int, default=0, help="analyse only the first N rules")
    p.add_argument("--csv", default="results.csv")
    p.add_argument("--min-variants", type=int, default=3,
                   help="a rule is called 'resistant' only if at least N non-trivial variants were all detected")
    p.add_argument("--verify-rsigma", action="store_true",
                   help="replay original + mutated events through rsigma and compare engines")
    p.add_argument("--rsigma", default=shutil.which("rsigma") or "rsigma")
    args = p.parse_args()

    paths = sorted(os.path.join(d, f) for d, _, fs in os.walk(args.directory)
                   for f in fs if f.endswith((".yml", ".yaml")))
    if args.limit:
        paths = paths[: args.limit]

    diffs: list = []
    rows = [analyse(path, args, diffs) for path in paths]
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
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

    def show(label: str, subset: list) -> None:
        v = collections.Counter(r["argv_verdict"] for r in subset)
        ev, rob, inc = v["evadable"], v["resistant"], v["inconclusive"]
        print(f"\n{label} ({len(subset)} rules):")
        print(f"  evadable     : {ev}  (at least one variant is NOT detected)")
        print(f"  resistant    : {rob}  (>= {args.min_variants} non-trivial variants, all detected)")
        print(f"  inconclusive : {inc}  (too few meaningful variants applicable)")
        if ev + rob:
            print(f"  -> among conclusive rules: {100 * ev / (ev + rob):.0f}% evadable")

    if scored:
        by_status = collections.Counter(r["program_status"] for r in scored)
        print(f"\nPrograms: {dict(by_status)}")
        show("Verdict, ALL rules (hypothesis for unvalidated programs)", scored)
        sole = [r for r in scored if not r["other_paths"]]
        show("Verdict, rules where CommandLine is the SOLE detection path", sole)
        show("Verdict, SOLE path AND program VALIDATED on Windows (strongest claim)",
             [r for r in sole if r["program_status"] == "validated"])
        print("\n('other path' = the rule can also fire another way, e.g. by binary name, so evading the"
              "\n command line alone does not evade the whole rule.)")
        print("\nSample of resistant rules (check them by hand):")
        for r in [r for r in scored if r["argv_verdict"] == "resistant"][:8]:
            print(f"  {r['mutations_argv']:>3} variants  {r['title']}  [{r['program']}]")
        print("\nUnvalidated programs most often seen (candidates to validate next):")
        unv = collections.Counter(r["program"] for r in scored if r["program_status"] == "unvalidated")
        for prog, n in unv.most_common(12):
            print(f"  {n:4}  {prog}")
        print("\n'resistant' only means the rule survived OUR mutators (for instance because its patterns are"
              "\n punctuation or very short tokens that quote insertion cannot touch). It is not proof of robustness.")
        print("\nNote: events are minimal; variants are validated only for the programs listed above.")

    if args.verify_rsigma:
        checked = [r for r in scored if r["engine_diffs"] != ""]
        total = sum(int(r["mutations_all"]) for r in checked)
        print(f"\nEngine comparison: {len(checked)} rules, {total} mutated events compared")
        print(f"  disagreements between sigma-mutate and rsigma: {len(diffs)}")
        for title, label, ours, ref, value in diffs[:15]:
            print(f"  - {title} | {label} | ours={ours} rsigma={ref}\n      {value}")

    print(f"\nDetails written to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
