"""A small Sigma matcher, covering what the SigmaHQ process_creation rules use.

Anything it does not understand raises NotImplementedError rather than guessing.
"""
from __future__ import annotations

import base64
import fnmatch
import re

_MODS = {"contains", "startswith", "endswith", "all", "windash", "base64", "base64offset", "re", "i", "m", "s"}
_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def parse_pattern(p: str) -> list[tuple]:
    # Sigma escapes: \\ is a backslash, \* and \? are literals. Any other backslash is kept as is.
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
    """Some string matching the pattern (wildcards become 'x')."""
    return "".join(part[1] if part[0] == "lit" else "x" for part in parse_pattern(str(p)))


def escape(s: str) -> str:
    """Inverse of literal_value for plain strings."""
    return s.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _plain(p: str) -> bytes:
    parts = parse_pattern(p)
    if any(x[0] != "lit" for x in parts):
        raise NotImplementedError("wildcards inside base64 values are not supported")
    return "".join(x[1] for x in parts).encode("utf-8")


def base64_variants(p: str, offset: bool) -> list[str]:
    """What the base64 / base64offset modifiers turn a value into (same rules as pySigma)."""
    raw = _plain(p)
    if not offset:
        return [base64.b64encode(raw).decode()]
    # The value can sit at any of three positions relative to base64 blocks; the characters
    # that also depend on neighbouring bytes are cut off.
    start, end = (0, 2, 3), (None, -3, -2)
    return [base64.b64encode(b" " * i + raw)[start[i]:end[(len(raw) + i) % 3]].decode() for i in range(3)]


_REGEX_CACHE: dict = {}
# windash: a dash can also be written as a slash, an en dash, an em dash or a horizontal bar.
_DASH_CLASS = r"[\-/–—―]"


def _regex(pattern: str, op: str, windash: bool = False):
    key = (pattern, op, windash)
    if key not in _REGEX_CACHE:
        parts = []
        for x in parse_pattern(pattern):
            if x[0] == "lit":
                parts.append("".join(_DASH_CLASS if (windash and ch == "-") else re.escape(ch) for ch in x[1]))
            else:
                parts.append(".*" if x[0] == "any" else ".")
        body = "".join(parts)
        if op in ("startswith", "equals"):
            body = r"\A" + body
        if op in ("endswith", "equals"):
            body = body + r"\Z"
        _REGEX_CACHE[key] = re.compile(body, re.IGNORECASE | re.DOTALL)
    return _REGEX_CACHE[key]


def user_regex(pattern: str, mods) -> re.Pattern:
    # Sigma regexes are case-sensitive unless the rule says |i or (?i).
    flags = 0
    for m in mods:
        flags |= _RE_FLAGS.get(m, 0)
    key = ("re", pattern, flags)
    if key not in _REGEX_CACHE:
        try:
            _REGEX_CACHE[key] = re.compile(pattern, flags)
        except re.error as e:
            raise NotImplementedError(f"regex not understood by Python: {e}")
    return _REGEX_CACHE[key]


def check_modifiers(mods) -> None:
    unknown = set(mods) - _MODS
    if unknown:
        raise NotImplementedError(f"unsupported modifier(s): {sorted(unknown)}")
    if "re" in mods:
        if set(mods) - {"re", "i", "m", "s", "all"}:
            raise NotImplementedError(f"unsupported modifier combination: {sorted(mods)}")
    elif set(mods) & {"i", "m", "s"}:
        raise NotImplementedError("regex flags without |re")
    if "base64offset" in mods and "contains" not in mods:
        raise NotImplementedError("base64offset without contains")


def expand(p: str, mods) -> list[str]:
    if "base64offset" in mods:
        return base64_variants(p, offset=True)
    if "base64" in mods:
        return base64_variants(p, offset=False)
    return [p]


def operator(mods) -> str:
    for op in ("contains", "startswith", "endswith"):
        if op in mods:
            return op
    return "equals"


def _field_matches(value, mods, patterns) -> bool:
    v = str(value)
    if "re" in mods:
        results = [bool(user_regex(str(p), mods).search(v)) for p in patterns]
    else:
        op, windash = operator(mods), "windash" in mods
        results = [any(_regex(alt, op, windash).search(v) for alt in expand(str(p), mods)) for p in patterns]
    return all(results) if "all" in mods else any(results)


def _selection_matches(sel, event) -> bool:
    if isinstance(sel, list) and all(isinstance(s, dict) for s in sel):
        return any(_selection_matches(s, event) for s in sel)
    if not isinstance(sel, dict):
        raise NotImplementedError("keyword selections are not supported yet")
    for key, expected in sel.items():
        field, *mods = key.split("|")
        check_modifiers(mods)
        if isinstance(expected, list) and any(e is None for e in expected):
            raise NotImplementedError("null inside a value list is not supported yet")
        if expected is None:  # absent or empty
            if event.get(field) not in (None, ""):
                return False
            continue
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
    det = rule["detection"]
    truth = {
        name: _selection_matches(sel, event)
        for name, sel in det.items()
        if name not in ("condition", "timeframe")
    }
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    return any(_eval_condition(c, truth) for c in conds)


eval_condition = _eval_condition
