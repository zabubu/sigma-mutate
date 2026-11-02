# sigma-mutate (working name)

Mutation testing for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

A rule that fires on `certutil -urlcache ... http://...` may stay silent on
`certutil -url""cache ... ht""tp://...`, a command that does exactly the same thing.
**sigma-mutate** rewrites a known true-positive event into variants that are equivalent
under a stated assumption, replays each variant against the rule, and reports which
variants slip through.

## Quick start

```bash
pip install -e .
sigma-mutate examples/certutil_rule.yml examples/certutil_event.json

# whole SigmaHQ folder, cross-checked against rsigma
python scripts/corpus.py path/to/sigma/rules/windows/process_creation --verify-rsigma
```

## How it works

1. **Synthesize** a minimal true-positive event from the rule itself (SigmaHQ ships none).
2. **Mutate** its `CommandLine` with deterministic mutators.
3. **Replay** every variant through the matcher; a variant that is no longer detected is an evasion.
4. **Cross-check** the matcher against [rsigma](https://github.com/timescale/rsigma) (reference engine).

## Mutators and assumptions

| Mutator | Assumption | Idea |
|---|---|---|
| `quote_split` | argv | `h""ttp` is parsed back to `http` |
| `quote_wrap` | argv | `"-urlcache"` is parsed back to `-urlcache` |
| `space_padding`, `tab_separator` | argv | whitespace tweaks (trivial) |
| `caret_insert` | cmd.exe | `h^ttp`, only if run through cmd.exe |
| `option_prefix_swap` | program | `-x` -> `/x`, only if the program accepts both |

`argv` = same result after standard Windows argument parsing. Only `argv` runs by default.

## Verdicts

Per rule: **evadable** (at least one undetected variant), **robust** (at least N non-trivial
variants, all detected) or **inconclusive** (too few meaningful variants to claim anything).

## Honest limitations

- Events are **minimal**: they contain what the rule asks for, not a realistic attack.
- Variants are **not yet validated on a real Windows host**; some programs do not use standard
  argument parsing. Planned: validate each mutator against representative programs.
- Only `CommandLine` is mutated; `re`, `base64offset` and `fieldref` rules are not supported yet.

## Status

v0.0.9 - matcher validated against rsigma on SigmaHQ `windows/process_creation`
(events and variants, no disagreement at last run).

## Roadmap

1. Validate mutators on Windows (sandbox) and publish the method
2. Support `re` / `base64offset`, mutate other fields (paths, parent command lines)
3. Benchmark all SigmaHQ rule folders and publish the results
4. Upstream fixes to SigmaHQ; GitHub Action

## Related work

Academic studies of Sigma rule evasion exist (e.g. arXiv:2311.10197), and other open-source
tools explore mutation-based evasion testing. This project's goal is a reproducible,
large-scale measurement plus upstream contributions.

## License

MIT
