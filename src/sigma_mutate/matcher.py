"""Minimal Sigma matcher (MVP).

Supports: field modifiers contains / startswith / endswith / all, wildcard
equality, list-of-maps selections, and conditions made of selection names with
and / or / not / parentheses. Matching is case-insensitive, like Sigma.

Anything else raises NotImplementedError instead of silently guessing.
Later milestone: cross-check this matcher against pySigma on the SigmaHQ corpus.
"""
from __future__ import annotations

import fnmatch
import re

_MODS = {"contains", "startswith", "endswith", "all"}


def _field_matches(value, mods, patterns) -> bool:
    v = str(value).lower()
    pats = [str(p).lower() for p in patterns]
    if "contains" in mods:
        test = lambda p: p in v
    elif "startswith" in mods:
        test = v.startswith
    elif "endswith" in mods:
        test = v.endswith
    else:
        test = lambda p: fnmatch.fnmatchcase(v, p)
    results = [test(p) for p in pats]
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
        if peek() == "of" or tok in ("all", "1"):
            raise NotImplementedError("'1 of' / 'all of' conditions are not supported yet")
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
