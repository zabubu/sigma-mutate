"""Turn the corpus run (verif.csv) and the Windows validation run (validation.csv) into RESULTS.md.

Usage:
    py scripts\\report.py
    py scripts\\report.py --corpus verif.csv --validation validation.csv --out RESULTS.md
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime
import os
import subprocess
import sys

VERDICTS = ("evadable", "resistant", "inconclusive")

STATUS_TEXT = {
    "scored": "tested",
    "no_commandline": "skipped: the rule does not look at the command line",
    "no_mutations": "skipped: no rewrite applies to its command line",
    "unsupported": "skipped: uses a Sigma feature the tool does not handle",
    "rsigma_disagrees": "skipped: the reference engine rejected the sample event",
    "error": "skipped: error during the run",
    "load_error": "skipped: invalid YAML",
    "skipped": "skipped: not a process-creation rule",
}

MUTATOR_TEXT = {
    "quote_split": 'empty quotes inside a word (`h""ttp`)',
    "quote_wrap": 'a word wrapped in quotes (`"-urlcache"`)',
    "space_padding": "double spaces",
    "tab_separator": "tabs instead of spaces",
    "caret_insert": "carets, through cmd.exe (`h^ttp`)",
    "option_prefix_swap": "`/x` instead of `-x`",
}


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def truthy(v: str) -> bool:
    return v.strip().lower() == "true"


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.0f}%" if b else "n/a"


def code(s: str) -> str:
    # inline code that survives a markdown table
    s = s.replace("|", "\\|").replace("\t", "<TAB>")
    fence = "``" if "`" in s else "`"
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def verdicts(rows: list[dict]) -> dict:
    c = collections.Counter(r["argv_verdict"] for r in rows)
    ev, res, inc = (c[v] for v in VERDICTS)
    return {"rules": len(rows), "evadable": ev, "resistant": res, "inconclusive": inc,
            "conclusive": ev + res, "share": pct(ev, ev + res)}


def sigma_commit(rows: list[dict]) -> str | None:
    for r in rows:
        d = os.path.dirname(r["path"])
        if os.path.isdir(d):
            try:
                out = subprocess.run(["git", "-C", d, "log", "-1", "--format=%h (%cs)"],
                                     capture_output=True, text=True, timeout=10)
                return out.stdout.strip() or None
            except (OSError, subprocess.SubprocessError):
                return None
    return None


def examples(scored: list[dict], n: int = 8) -> list[dict]:
    picked, programs = [], set()
    candidates = [r for r in scored if r["argv_verdict"] == "evadable" and r.get("example")
                  and not truthy(r["other_paths"]) and r["program_status"] == "validated"]
    candidates += [r for r in scored if r["argv_verdict"] == "evadable" and r.get("example")
                   and not truthy(r["other_paths"]) and r not in candidates]
    for r in candidates:
        if r["program"] in programs or len(r["example"]) > 90:
            continue
        programs.add(r["program"])
        picked.append(r)
        if len(picked) == n:
            break
    return picked


def validation_summary(rows: list[dict]):
    groups = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    blocked = 0
    for r in rows:
        if r["equivalent"] == "":
            blocked += 1
            continue
        cell = groups[(r["mutator"], r["assumption"], r["kind"])][r["program"]]
        cell[0] += truthy(r["equivalent"])
        cell[1] += 1
    out = []
    for (mutator, assumption, kind), progs in sorted(groups.items()):
        ok = sum(c[0] for c in progs.values())
        total = sum(c[1] for c in progs.values())
        failing = sorted(p for p, c in progs.items() if c[0] != c[1])
        out.append((mutator, assumption, kind, ok, total, failing))
    return out, blocked


def render(corpus: list[dict], validation: list[dict] | None, commit: str | None) -> str:
    scored = [r for r in corpus if r["status"] == "scored"]
    sole = [r for r in scored if not truthy(r["other_paths"])]
    strict = [r for r in sole if r["program_status"] == "validated"]
    v_all, v_sole, v_strict = verdicts(scored), verdicts(sole), verdicts(strict)
    checked = [r for r in scored if r["engine_diffs"] != ""]
    compared = sum(int(r["mutations_all"]) + 1 for r in checked)
    diffs = sum(int(r["engine_diffs"]) for r in checked)
    ex = examples(scored)

    L: list[str] = []
    add = L.append
    add("# Results")
    add("")
    add("## The key figures")
    add("")
    add(f"> **{v_all['share']}** of the detection rules tested can be sidestepped by retyping the attack command "
        f"differently ({v_all['evadable']} of {v_all['conclusive']} rules).")
    add(">")
    add(f"> **{v_strict['share']}** with the most cautious count ({v_strict['evadable']} of "
        f"{v_strict['conclusive']} rules).")
    add("")
    add("**What this means.** A detection rule is meant to raise an alert when an attacker runs a suspicious "
        "command. For almost every rule tested, adding a pair of quote marks or an extra space to that command "
        "is enough to avoid the alert, while the command does exactly the same thing on the computer.")
    add("")
    add("**Why two figures.** The first counts every rule that gave a clear answer. The second keeps only the "
        "cases where there is no room for doubt: rules that have no other way to raise an alert, about "
        "programs whose behaviour was checked on a real Windows computer. Even this cautious reading leaves "
        f"about {round(v_strict['evadable'] / v_strict['conclusive'] * 10) if v_strict['conclusive'] else 0} "
        "rules in 10 open to the bypass.")
    add("")
    if ex:
        r = min(ex, key=lambda r: ("  " in r["original"], len(r["original"])))
        add(f"**A real example.** The rule _{r['title']}_ raises an alert for the first command below but not "
            f"for the second. Windows treats them as the same command.")
        add("")
        add("```")
        add(r["original"])
        add(r["example"])
        add("```")
        add("")
    add("**How sure are these numbers?**")
    add("")
    add(f"- {len(corpus):,} public rules were examined and {len(scored)} could be tested automatically.")
    if validation:
        groups, _ = validation_summary(validation)
        progs = len({r["program"] for r in validation})
        argv_rows = [g for g in groups if g[1] == "argv"]
        ok = sum(g[3] for g in argv_rows)
        tot = sum(g[4] for g in argv_rows)
        add(f"- The rewritten commands were really run on Windows with {progs} common programs: {ok} of {tot} "
            f"gave exactly the same result as the original.")
    if checked:
        add(f"- Every verdict ({compared:,} in total) was double-checked by an independent rule engine (rsigma): "
            f"{diffs} disagreement{'s' if diffs != 1 else ''}.")
    add("")
    add("The rest of this page gives the detailed tables. The [README](README.md) explains the problem, "
        "[METHODOLOGY.md](METHODOLOGY.md) explains the method.")
    add("")

    add("## What was tested")
    add("")
    add("| Rules | Count |")
    add("|---|---:|")
    for status, n in collections.Counter(r["status"] for r in corpus).most_common():
        add(f"| {STATUS_TEXT.get(status, status)} | {n} |")
    add(f"| **total** | **{len(corpus)}** |")
    add("")
    unsupported = collections.Counter(r["reason"] for r in corpus if r["status"] == "unsupported")
    if unsupported:
        add("Reasons for unsupported rules: " + "; ".join(f"{reason} ({n})" for reason, n in unsupported.most_common(5)) + ".")
        add("")
    for r in corpus:
        if r["status"] == "error":
            cause = "the antivirus blocked a temporary file" if "antivirus" in r["reason"] else r["reason"]
            add(f"Error on _{r['title']}_: {cause}.")
            add("")

    add("## Verdicts")
    add("")
    add("Only rewrites that are equivalent under standard Windows argument parsing are counted here.")
    add("")
    add("- **evadable**: at least one rewritten command is not detected.")
    add("- **resistant**: at least 3 meaningful rewrites, all detected. This only means the rule survived "
        "these particular rewrites.")
    add("- **inconclusive**: too few meaningful rewrites applied to say anything.")
    add("")
    add("| Scope | Rules | Evadable | Resistant | Inconclusive | Evadable among clear answers |")
    add("|---|---:|---:|---:|---:|---:|")
    for label, v in (("All tested rules", v_all),
                     ("Command line is the only way the rule fires", v_sole),
                     ("Same, and program validated on Windows", v_strict)):
        add(f"| {label} | {v['rules']} | {v['evadable']} | {v['resistant']} | {v['inconclusive']} | {v['share']} |")
    add("")

    if ex:
        add("## Examples")
        add("")
        add("| Rule | Detected | Not detected |")
        add("|---|---|---|")
        for r in ex:
            add(f"| {r['title'].replace('|', '/')} | {code(r['original'])} | {code(r['example'])} |")
        add("")
        add("Sample events are minimal: they contain what the rule looks for, not a full attack.")
        add("")

    top = collections.Counter(r["program"] for r in scored if r["argv_verdict"] == "evadable")
    if top:
        add("## Programs with the most evadable rules")
        add("")
        add("| Program | Evadable rules | Validated on Windows |")
        add("|---|---:|---|")
        status = {r["program"]: r["program_status"] for r in scored}
        for prog, n in top.most_common(10):
            add(f"| {prog} | {n} | {'yes' if status[prog] == 'validated' else 'no'} |")
        add("")

    if validation:
        groups, blocked = validation_summary(validation)
        add("## Are the rewritten commands really equivalent?")
        add("")
        add("`scripts/validate_mutators.py` runs harmless commands and their rewrites on a real Windows machine "
            "and compares exit code and output. Programs tested: "
            + ", ".join(sorted({r["program"] for r in validation})) + ".")
        add("")
        add("Assumptions: **argv** means standard Windows argument parsing (used by default), **cmd.exe** means "
            "the command goes through cmd.exe, **program** means it depends on the program.")
        add("")
        add("| Rewrite | Applies to | Assumption | Same result | Programs where it differs |")
        add("|---|---|---|---:|---|")
        for mutator, assumption, kind, ok, total, failing in groups:
            add(f"| {MUTATOR_TEXT.get(mutator, mutator)} | {kind} | {assumption} | {ok}/{total} | "
                f"{', '.join(failing) or '-'} |")
        add("")
        via_cmd = [r for r in validation if r["assumption"] == "cmd.exe" and r["works_directly"] != ""]
        if via_cmd:
            direct = sum(truthy(r["works_directly"]) for r in via_cmd)
            add(f"The cmd.exe rewrites were also launched without cmd.exe: {direct} of {len(via_cmd)} still worked, "
                f"which is why they are not assumed valid in general.")
            add("")
        if blocked:
            add(f"{blocked} launch{'es were' if blocked > 1 else ' was'} refused by Windows (access denied, most "
                f"likely the antivirus) and {'are' if blocked > 1 else 'is'} not counted.")
            add("")
        add("How the tool uses this: `net.exe` and `wmic.exe` do not split arguments on tabs and `wmic.exe` keeps "
            "inner quotes, so those rewrites are not assumed valid for them; `cmd.exe` parses its own command "
            "line, so quote rewrites of its arguments are not assumed valid either; `schtasks.exe` gave unstable "
            "output in an earlier run and is not counted as validated yet.")
        add("")

    if checked:
        add("## Agreement with a reference engine")
        add("")
        add(f"Every sample event and every rewrite ({compared:,} events, {len(checked)} rules) was also evaluated "
            f"by [rsigma](https://github.com/timescale/rsigma). Disagreements: **{diffs}**.")
        add("")

    add("## Limits")
    add("")
    add("- Only the command line is rewritten. A rule that also checks the program path or the parent process "
        "is counted separately (\"only way the rule fires\").")
    add("- Sample events are built from the rules themselves, so they are minimal.")
    add("- Rewrites are validated for the programs listed above only; for other programs the result relies on "
        "standard Windows argument parsing, which most but not all programs use.")
    add("- See [METHODOLOGY.md](METHODOLOGY.md) for the full method.")
    add("")
    add("## Reproduce")
    add("")
    src = "the public [SigmaHQ](https://github.com/SigmaHQ/sigma) rule library"
    if commit:
        src += f" (commit {commit})"
    add(f"This page was generated by `scripts/report.py` on {datetime.date.today().isoformat()} from `verif.csv` "
        f"and `validation.csv`. Rules come from {src}, folder `rules/windows/process_creation`.")
    add("")
    add("```")
    add("python scripts/corpus.py path/to/sigma/rules/windows/process_creation --verify-rsigma --csv verif.csv")
    add("python scripts/validate_mutators.py          # Windows only")
    add("python scripts/report.py")
    add("```")
    add("")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus", default="verif.csv")
    p.add_argument("--validation", default="validation.csv")
    p.add_argument("--out", default="RESULTS.md")
    a = p.parse_args()

    if not os.path.isfile(a.corpus):
        print(f"{a.corpus} not found: run scripts/corpus.py first", file=sys.stderr)
        return 2
    corpus = read_csv(a.corpus)
    missing = {"status", "argv_verdict", "other_paths", "program_status", "engine_diffs"} - set(corpus[0] if corpus else {})
    if missing:
        print(f"{a.corpus} lacks columns {sorted(missing)}: regenerate it with scripts/corpus.py", file=sys.stderr)
        return 2
    validation = read_csv(a.validation) if os.path.isfile(a.validation) else None
    if validation is None:
        print(f"note: {a.validation} not found, the Windows validation section is left out", file=sys.stderr)

    text = render(corpus, validation, sigma_commit(corpus))
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
