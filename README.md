# sigma-mutate (working name)

Mutation testing for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

A rule that fires on `certutil -urlcache ... http://...` may stay silent on
`certutil -url""cache ... ht""tp://...`, a command that does exactly the same thing.
**sigma-mutate** rewrites a known true-positive event into semantically equivalent
variants, replays each variant against the rule, and reports which variants slip through.

## Quick start

```bash
pip install -e .
sigma-mutate examples/certutil_rule.yml examples/certutil_event.json
```

## Design principles

- **Semantic validity first.** Each mutator declares the assumption under which a variant is
  equivalent (`argv`, `cmd.exe`, `program`). Only `argv` runs by default.
- **Reproducible.** Deterministic mutators, no hidden randomness.
- **CI-friendly.** `--fail-under 0.8` exits non-zero when robustness regresses.

## Status

MVP (v0.0.1): minimal Sigma matcher, 4 mutators on `CommandLine`, per-rule score.

## Roadmap

1. Cross-check the matcher against pySigma on the full SigmaHQ corpus
2. Support more Sigma features (`1 of`, `re`, `base64`, keywords)
3. Add semantic mutators (equivalent utilities, argument reordering)
4. Benchmark every SigmaHQ `process_creation` rule and publish the results
5. Upstream fixes to SigmaHQ; GitHub Action

## Related work

Academic studies of Sigma rule evasion exist (e.g. arXiv:2311.10197), and other open-source
tools explore mutation-based evasion testing. This project's goal is a reproducible,
large-scale measurement plus upstream contributions.

## License

MIT
