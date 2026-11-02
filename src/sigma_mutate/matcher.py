"""Minimal Sigma matcher (MVP).

Supports: field modifiers contains / startswith / endswith / all, wildcards (* ?) and
Sigma escapes (\\\\ \\* \\?), list-of-maps selections, and conditions made of selection names with
and / or / not / parentheses and '1 of X*' / 'all of them' quantifiers. Matching is case-insensitive, like Sigma.

Anything else raises NotImplementedError instead of silently guessing.
Later milestone: cross-check this matcher against pySigma on the SigmaHQ corpus.
"""
from __future__ import annotations

import fnmatch
import re

_MODS = {"contains", "startswith", "endswith", "all"}


def parse_pattern(p: str) -> list[tuple]:
    """Parse a Sigma value: '\\\\' -> backslash, '\\*' and '\\?' -> literals, '*' / '?' -> wildcards.

    A backslash followed by anything else stays a literal backslash (Sigma spec).
    """
    out: list[tuple] = []
    buf: list[str] = []

    def flush():
        if buf:
            out.append(("lit", "".join(buf)))
            buf.clear()

    i = 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p) and p[i + 1] in "\\*?":
            buf.append(p[i + 1])
            i += 2
            continue
        if c in "*?":
            flush()
            out.append(("any",) if c == "*" else ("one",))
        else:
            buf.append(c)
        i += 1
    flush()
    return out


def literal_value(p) -> str:
    """A concrete string that matches the pattern (wildcards replaced by 'x')."""
    return "".join(part[1] if part[0] == "lit" else "x" for part in parse_pattern(str(p)))


_REGEX_CACHE: dict = {}


def _regex(pattern: str, op: str):
    key = (pattern, op)
    if key not in _REGEX_CACHE:
        body = "".join(
            re.escape(x[1]) if x[0] == "lit" else (".*" if x[0] == "any" else ".")
            for x in parse_pattern(pattern)
        )
        if op in ("startswith", "equals"):
            body = r"\A" + body
        if op in ("endswith", "equals"):
            body = body + r"\Z"
        _REGEX_CACHE[key] = re.compile(body, re.IGNORECASE | re.DOTALL)
    return _REGEX_CACHE[key]


def _field_matches(value, mods, patterns) -> bool:
    v = str(value)
    op = ("contains" if "contains" in mods else "startswith" if "startswith" in mods
          else "endswith" if "endswith" in mods else "equals")
    results = [bool(_regex(str(p), op).search(v)) for p in patterns]
    return all(results) if "all" in mods else any(results)


def _selection_matches(sel, event) -> bool:
    if isinstance(sel, list) and all(isinstance(s, dict) for s in sel):
        return any(_selection_matches(s, event) for s in sel)
    if not isinstance(sel, dict):
        raise NotImplementedError("keyword selections are not supported yet")
    for key, expected in sel.items():
        field, *mods = key.split("|")
        unknown = set(mods) - _MODS
        if unknown:
            raise NotImplementedError(f"unsupported modifier(s): {sorted(unknown)}")
        if expected is None:
            raise NotImplementedError("null values (field must be absent) are not supported yet")
        if field not in event:
            return False
        patterns = expected if isinstance(expected, list) else [expected]
        if not _field_matches(event[field], mods, patterns):
            return False
    return True


_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _eval_condition(cond: str, truth: dict) -> bool:
    toks = _TOKEN.findall(cond)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        tok = toks[pos]
        pos += 1
        return tok

    def or_():
        v = and_()
        while peek() == "or":
            take()
            r = and_()
            v = v or r
        return v

    def and_():
        v = not_()
        while peek() == "and":
            take()
            r = not_()
            v = v and r
        return v

    def not_():
        if peek() == "not":
            take()
            return not not_()
        return atom()

    def atom():
        tok = take()
        if tok == "(":
            v = or_()
            if peek() != ")":
                raise ValueError("missing closing parenthesis in condition")
            take()
            return v
        if peek() == "of":
            take()
            if peek() is None:
                raise ValueError("missing pattern after 'of'")
            pattern = take()
            if tok != "all" and not tok.isdigit():
                raise ValueError(f"invalid quantifier before 'of': {tok}")
            names = [n for n in truth if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise ValueError(f"no selection matches '{pattern}'")
            hits = sum(truth[n] for n in names)
            return hits == len(names) if tok == "all" else hits >= int(tok)
        if tok not in truth:
            raise ValueError(f"unknown selection in condition: {tok}")
        return truth[tok]

    result = or_()
    if pos != len(toks):
        raise ValueError(f"unexpected token in condition: {toks[pos]}")
    return result


def matches(rule: dict, event: dict) -> bool:
    """Return True if the Sigma rule (parsed YAML dict) fires on the event."""
    det = rule["detection"]
    truth = {
        name: _selection_matches(sel, event)
        for name, sel in det.items()
        if name not in ("condition", "timeframe")
    }
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    return any(_eval_condition(c, truth) for c in conds)


# Public aliases used by the event synthesizer.
eval_condition = _eval_condition
SUPPORTED_MODIFIERS = _MODS
