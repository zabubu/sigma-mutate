# sigma-mutate

**A crash test for cyberattack detection rules.** It checks whether a rule that spots an attack
still spots it when the attacker types the same command slightly differently. Tested on 1,193
public rules: **97% of them can be sidestepped this way.**

## The problem

To catch hackers, companies use *detection rules*. A rule says something like: "if someone uses
this Windows tool to download a file from the internet, raise an alert". Most rules work by
looking for specific words in the command the attacker typed.

The catch: Windows accepts many spellings of the same command. Adding two quote marks in the
middle of a word, for example, changes nothing for Windows, which removes them before running
the command:

```
certutil -urlcache http://...         ← the rule sees "urlcache": alert
certutil -url""cache http://...       ← same action, the rule sees nothing
```

The attack runs exactly the same way, but no alert is raised.

## Why it matters

These rules are not obscure. They come from [Sigma](https://github.com/SigmaHQ/sigma), the open
format the security community uses to share detection rules. Its public library is reused by
companies and security products around the world. A rule that two quote marks can defeat gives
a false sense of safety, and an attacker needs no skill at all to get past it.

## What the project proves

The tool tested every Windows rule of that library that watches programs being launched
(1,193 rules). For each one it built a command the rule catches, rewrote it in ways that change
nothing for Windows, and checked whether the rule still fired.

| | |
|---|---|
| Rules that could be tested | **894** |
| Rules that miss at least one rewritten command | **97%** (834 of 864 with a clear answer) |
| Same, counting only the most certain cases | **91%** (173 of 191) |

In plain words: for almost every rule, an attacker can avoid the alert by adding quotes or
spaces to the command. The 91% figure keeps only rules that have no other way to raise an alert
and programs whose behaviour was checked on a real Windows computer. It is the most cautious
reading, and the conclusion holds.

This does not mean attacks go unnoticed everywhere: companies usually have several layers of
defence. It means one widely shared layer has a measurable weakness, and that weakness can be
fixed.

## Why the results can be trusted

A claim like "97% of rules fail" is only worth something if the measurement is right. The
project checks itself at every step:

- **The rewritten commands really are equivalent.** They were actually run on a Windows computer
  with 15 common programs. All 193 rewrites the tool uses by default gave exactly the same result
  as the original. The few rewrites that only work with some programs were found this way and
  are left out.
- **The verdicts are double-checked.** The project includes its own engine that reads and applies
  the rules. Its 22,002 verdicts were compared with those of an independent, existing engine
  (rsigma): no disagreement.
- **Nothing is hand-picked.** The library has no sample attacks, so the tool builds a test case
  automatically for each rule, including rules written as complex text patterns. Every number can
  be regenerated with three commands, and automated tests run on every change.

## Who it is for

Teams that write or deploy detection rules can run sigma-mutate on their rules before putting
them in production. It shows exactly which rewritten commands slip through, so the rule can be
fixed, in the same way that software tests catch bugs before release.

## Learn more

- [RESULTS.md](RESULTS.md): all the figures, with real examples of rules and the commands they miss.
- [METHODOLOGY.md](METHODOLOGY.md): how it works in detail, what is supported and the limits.

## Try it

Requires Python 3.10 or newer.

```bash
pip install -e .

# one rule, one event
sigma-mutate examples/certutil_rule.yml examples/certutil_event.json

# a whole folder of Sigma rules, then the report
python scripts/corpus.py path/to/sigma/rules/windows/process_creation --verify-rsigma
python scripts/report.py
```

`--verify-rsigma` needs [rsigma](https://github.com/timescale/rsigma) on the PATH.
`scripts/validate_mutators.py` reruns the Windows check (Windows only, harmless read-only
commands).

## License

MIT, see [LICENSE](LICENSE).
