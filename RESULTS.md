# Results

## The key figures

> **97%** of the detection rules tested can be sidestepped by retyping the attack command differently (834 of 864 rules).
>
> **91%** with the most cautious count (173 of 191 rules).

**What this means.** A detection rule is meant to raise an alert when an attacker runs a suspicious command. For almost every rule tested, adding a pair of quote marks or an extra space to that command is enough to avoid the alert, while the command does exactly the same thing on the computer.

**Why two figures.** The first counts every rule that gave a clear answer. The second keeps only the cases where there is no room for doubt: rules that have no other way to raise an alert, about programs whose behaviour was checked on a real Windows computer. Even this cautious reading leaves about 9 rules in 10 open to the bypass.

**A real example.** The rule _New Root Certificate Installed Via Certutil.EXE_ raises an alert for the first command below but not for the second. Windows treats them as the same command.

```
certutil.exe -addstore root
certutil.exe -""addstore root
```

**How sure are these numbers?**

- 1,193 public rules were examined and 894 could be tested automatically.
- The rewritten commands were really run on Windows with 15 common programs: 193 of 193 gave exactly the same result as the original.
- Every verdict (22,002 in total) was double-checked by an independent rule engine (rsigma): 0 disagreements.

The rest of this page gives the detailed tables. The [README](README.md) explains the problem, [METHODOLOGY.md](METHODOLOGY.md) explains the method.

## What was tested

| Rules | Count |
|---|---:|
| tested | 894 |
| skipped: the rule does not look at the command line | 293 |
| skipped: uses a Sigma feature the tool does not handle | 5 |
| skipped: error during the run | 1 |
| **total** | **1193** |

Reasons for unsupported rules: no simple selection set satisfies the condition (3); unsupported feature: unsupported modifier(s): ['fieldref'] (1); synthesized event does not satisfy the rule (1).

Error on _Mshtml.DLL RunHTMLApplication Suspicious Usage_: the antivirus blocked a temporary file.

## Verdicts

Only rewrites that are equivalent under standard Windows argument parsing are counted here.

- **evadable**: at least one rewritten command is not detected.
- **resistant**: at least 3 meaningful rewrites, all detected. This only means the rule survived these particular rewrites.
- **inconclusive**: too few meaningful rewrites applied to say anything.

| Scope | Rules | Evadable | Resistant | Inconclusive | Evadable among clear answers |
|---|---:|---:|---:|---:|---:|
| All tested rules | 894 | 834 | 30 | 30 | 97% |
| Command line is the only way the rule fires | 798 | 750 | 28 | 20 | 96% |
| Same, and program validated on Windows | 192 | 173 | 18 | 1 | 91% |

## Examples

| Rule | Detected | Not detected |
|---|---|---|
| Windows AMSI Related Registry Tampering Via CommandLine | `reg.exe \Software\Microsoft\Windows Script\Settings AmsiEnable add` | `reg.exe \S""oftware\Microsoft\Windows Script\Settings AmsiEnable add` |
| Suspicious Autorun Registry Modified via WMI | `wmic.exe reg  add \Software\Microsoft\Windows\CurrentVersion\Run :\Perflogs` | `wmic.exe reg  "add" \Software\Microsoft\Windows\CurrentVersion\Run :\Perflogs` |
| File Download Via Bitsadmin | `bitsadmin.exe  /transfer ` | `bitsadmin.exe  /""transfer ` |
| New Root Certificate Installed Via Certutil.EXE | `certutil.exe -addstore root` | `certutil.exe -""addstore root` |
| New DMSA Service Account Created in Specific OUs | `powershell.exe New-ADServiceAccount -CreateDelegatedServiceAccount -path` | `powershell.exe N""ew-ADServiceAccount -CreateDelegatedServiceAccount -path` |
| Potential Cookies Session Hijacking | `curl.exe  -c ` | `curl.exe  -""c ` |
| Remote File Download Via Findstr.EXE | `findstr  -v   -l \\` | `findstr  -""v   -l \\` |
| Suspicious Group And Account Reconnaissance Activity Using Net.EXE | `net.exe  group  domain admins` | `net.exe  g""roup  domain admins` |

Sample events are minimal: they contain what the rule looks for, not a full attack.

## Programs with the most evadable rules

| Program | Evadable rules | Validated on Windows |
|---|---:|---|
| (unspecified) | 222 | no |
| powershell.exe | 58 | yes |
| reg.exe | 32 | yes |
| schtasks.exe | 24 | no |
| rundll32.exe | 20 | no |
| cmd.exe | 16 | no |
| net.exe | 16 | yes |
| netsh.exe | 13 | yes |
| curl.exe | 12 | yes |
| sc.exe | 12 | yes |

## Are the rewritten commands really equivalent?

`scripts/validate_mutators.py` runs harmless commands and their rewrites on a real Windows machine and compares exit code and output. Programs tested: bitsadmin, certutil, cmd-type, curl, findstr, net, netsh, powershell, reg, sc, schtasks, sort, where, whoami, wmic.

Assumptions: **argv** means standard Windows argument parsing (used by default), **cmd.exe** means the command goes through cmd.exe, **program** means it depends on the program.

| Rewrite | Applies to | Assumption | Same result | Programs where it differs |
|---|---|---|---:|---|
| carets, through cmd.exe (`h^ttp`) | argument | cmd.exe | 93/93 | - |
| carets, through cmd.exe (`h^ttp`) | program name | cmd.exe | 44/44 | - |
| `/x` instead of `-x` | argument | program | 4/4 | - |
| empty quotes inside a word (`h""ttp`) | argument | argv | 103/103 | - |
| empty quotes inside a word (`h""ttp`) | program name | cmd.exe | 45/45 | - |
| empty quotes inside a word (`h""ttp`) | argument | program | 3/18 | cmd-type, wmic |
| a word wrapped in quotes (`"-urlcache"`) | argument | argv | 47/47 | - |
| a word wrapped in quotes (`"-urlcache"`) | program name | argv | 15/15 | - |
| a word wrapped in quotes (`"-urlcache"`) | argument | program | 3/4 | cmd-type |
| double spaces | argument | argv | 15/15 | - |
| tabs instead of spaces | argument | argv | 13/13 | - |
| tabs instead of spaces | argument | program | 0/2 | net, wmic |

The cmd.exe rewrites were also launched without cmd.exe: 8 of 183 still worked, which is why they are not assumed valid in general.

1 launch was refused by Windows (access denied, most likely the antivirus) and is not counted.

How the tool uses this: `net.exe` and `wmic.exe` do not split arguments on tabs and `wmic.exe` keeps inner quotes, so those rewrites are not assumed valid for them; `cmd.exe` parses its own command line, so quote rewrites of its arguments are not assumed valid either; `schtasks.exe` gave unstable output in an earlier run and is not counted as validated yet.

## Agreement with a reference engine

Every sample event and every rewrite (22,002 events, 894 rules) was also evaluated by [rsigma](https://github.com/timescale/rsigma). Disagreements: **0**.

## Limits

- Only the command line is rewritten. A rule that also checks the program path or the parent process is counted separately ("only way the rule fires").
- Sample events are built from the rules themselves, so they are minimal.
- Rewrites are validated for the programs listed above only; for other programs the result relies on standard Windows argument parsing, which most but not all programs use.
- See [METHODOLOGY.md](METHODOLOGY.md) for the full method.

## Reproduce

This page was generated by `scripts/report.py` on 2026-11-04 from `verif.csv` and `validation.csv`. Rules come from the public [SigmaHQ](https://github.com/SigmaHQ/sigma) rule library (commit 05d1031f5 (2026-10-21)), folder `rules/windows/process_creation`.

```
python scripts/corpus.py path/to/sigma/rules/windows/process_creation --verify-rsigma --csv verif.csv
python scripts/validate_mutators.py          # Windows only
python scripts/report.py
```
