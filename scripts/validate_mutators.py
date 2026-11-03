"""Validate the mutators on a REAL Windows host, with harmless commands.

For each test program, run the original command line and every 'argv' variant, then compare
exit code and output. This checks the assumption behind each mutator ("Windows parses the
variant like the original") per program, instead of taking it on faith.

Safe by design: read-only commands and one temporary text file (deleted at the end).
Note: some security products flag obfuscated command lines, even harmless ones.

Usage (Windows only):
    py scripts\\validate_mutators.py
    py scripts\\validate_mutators.py --dry-run     # list the commands without running them
    py scripts\\validate_mutators.py --assumptions argv
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sigma_mutate.mutators import generate  # noqa: E402


def test_commands(tmp_file: str) -> list[tuple[str, str]]:
    """(program label, command line). No quotes in the originals: the mutators assume none."""
    return [
        ("certutil", f"certutil.exe -hashfile {tmp_file} SHA256"),
        ("whoami", "whoami.exe /groups /fo csv"),
        ("reg", r"reg.exe query HKCU\Environment"),
        ("findstr", f"findstr.exe /i /c:hello {tmp_file}"),
        ("sort", f"sort.exe /r {tmp_file}"),
        ("cmd-type", f"cmd.exe /c type {tmp_file}"),
        ("powershell", "powershell.exe -NoProfile -NonInteractive -Command Write-Output hello"),
        ("curl", "curl.exe --version"),
        ("where", "where.exe /q cmd.exe"),
        ("schtasks", "schtasks.exe /query /fo csv /nh"),
        ("net", "net.exe accounts"),
        ("netsh", "netsh.exe interface show interface"),
        ("sc", "sc.exe query wuauserv"),
        ("bitsadmin", "bitsadmin.exe /list"),
        ("wmic", "wmic.exe os get caption"),
    ]


def run(cmdline: str):
    """Run a raw command line (passed unchanged to CreateProcess). -> (exit code, stdout, stderr)."""
    try:
        p = subprocess.run(cmdline, capture_output=True, text=True, errors="replace", timeout=30,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return "not-found", "", ""
    except subprocess.TimeoutExpired:
        return "timeout", "", ""
    except OSError as e:
        return f"oserror:{e.winerror if hasattr(e, 'winerror') else e}", "", ""


def launch(m_assumption: str, cmdline: str):
    """Variants that assume cmd.exe are run through cmd.exe, the others directly."""
    return run("cmd.exe /d /c " + cmdline) if m_assumption == "cmd.exe" else run(cmdline)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--assumptions", default="argv,cmd.exe", help="comma list: argv,cmd.exe,program")
    ap.add_argument("--csv", default="validation.csv")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if os.name != "nt" and not args.dry_run:
        print("This script must run on Windows (use --dry-run elsewhere).")
        return 2

    workdir = tempfile.mkdtemp(prefix="sigma_mutate_")
    tmp_file = os.path.join(workdir, "sample.txt")
    with open(tmp_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("hello world\n")
    assumptions = tuple(args.assumptions.split(","))
    rows = []
    try:
        for program, cmd in test_commands(tmp_file):
            muts = generate(cmd, assumptions)
            if args.dry_run:
                print(f"{program}: {len(muts)} variants of: {cmd}")
                continue
            base = run(cmd)
            print(f"{program}: original exit={base[0]}, {len(muts)} variants ...", flush=True)
            if base[0] != 0:
                print(f"  skipped: the original command did not succeed ({base[0]}), results would be meaningless")
                continue
            for m in muts:
                res = launch(m.assumption, m.value)
                blocked = str(res[0]).startswith("oserror")
                same = None if blocked else (res[0], res[1]) == (base[0], base[1])
                direct = ""
                if m.assumption == "cmd.exe":  # would it also work WITHOUT cmd.exe? (justifies the assumption)
                    d = run(m.value)
                    direct = (d[0], d[1]) == (base[0], base[1])
                kind = "program name" if m.label.startswith("token 0") else "argument"
                rows.append({"program": program, "mutator": m.mutator, "assumption": m.assumption, "kind": kind,
                             "label": m.label, "equivalent": same, "works_directly": direct, "exit": res[0],
                             "output_start": res[1][:60].replace("\n", " | "), "expected_start": base[1][:60].replace("\n", " | "),
                             "variant": m.value})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if args.dry_run:
        return 0

    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\nEquivalent / total per mutator and kind of token (blocked launches excluded):")
    by = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    blocked_rows = [r for r in rows if r["equivalent"] is None]
    for r in rows:
        if r["equivalent"] is None:
            continue
        cell = by[(r["mutator"], r["assumption"], r["kind"])][r["program"]]
        cell[0] += r["equivalent"]
        cell[1] += 1
    for (mutator, assumption, kind), progs in sorted(by.items()):
        ok = sum(c[0] for c in progs.values())
        total = sum(c[1] for c in progs.values())
        bad_progs = [f"{p} ({c[0]}/{c[1]})" for p, c in progs.items() if c[0] != c[1]]
        line = f"  {mutator:18} [{assumption}] {kind:12} {ok}/{total}"
        line += f"   differs on: {', '.join(bad_progs)}" if bad_progs else "   OK on all programs"
        if assumption == "cmd.exe":
            direct = [r for r in rows if (r["mutator"], r["assumption"], r["kind"]) == (mutator, assumption, kind)
                      and r["works_directly"] != ""]
            line += f"   | also works WITHOUT cmd.exe: {sum(bool(r['works_directly']) for r in direct)}/{len(direct)}"
        print(line)
    if blocked_rows:
        print(f"\nBlocked launches (access denied, probably antivirus): {len(blocked_rows)} - re-run to confirm")
        for r in blocked_rows[:5]:
            print(f"  {r['program']} | {r['mutator']} {r['label']} -> {r['exit']}")
    bad = [r for r in rows if r["equivalent"] is False]
    if bad:
        print("\nExamples of differences (up to 10):")
        for r in bad[:10]:
            print(f"  {r['program']} | {r['mutator']} {r['label']} -> exit {r['exit']}")
            print(f"      variant : {r['variant']}")
            print(f"      output  : {r['output_start']!r}")
            print(f"      expected: {r['expected_start']!r}")
    print(f"\nDetails written to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
