"""Synthesize a minimal true-positive event from a Sigma rule.

SigmaHQ rules ship without matching events, so we build one from the rule itself:
  1. pick a set of selections that makes the condition true,
  2. for each chosen selection pick one alternative (list-of-maps) and one value (lists),
  3. build a value for each constrained field,
  4. add harmless filler values so that "field is null" filters do not fire,
  5. verify the result with the matcher; try other combinations if it fails.

Caveat: synthesized command lines are minimal (they contain what the rule asks for,
not a realistic attack), so scores measure the rule's fragility on its own patterns.
"""
from __future__ import annotations

import re
from itertools import combinations, islice, product

from .matcher import (SUPPORTED_MODIFIERS, _selection_matches, eval_condition,
                      literal_value, matches)

MAX_SELECTION_SETS = 5   # how many different "true" selection sets to try
MAX_CANDIDATES = 60      # how many alternative/value combinations per selection set


class SynthError(Exception):
    """The rule cannot be turned into an event (reason in the message)."""


# ---------------------------------------------------------------- selection sets
def _candidates(names):
    """Small selection sets first, then 'everything' and 'everything but one'."""
    seen = set()
    for k in range(0, min(len(names), 3) + 1):
        for c in combinations(names, k):
            seen.add(c)
            yield c
    for c in [tuple(names)] + [tuple(n for n in names if n != s) for s in names]:
        if c not in seen:
            seen.add(c)
            yield c


def iter_satisfying(det: dict):
    names = [k for k in det if k not in ("condition", "timeframe")]
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    found = False
    for chosen in _candidates(names):
        truth = {n: (n in chosen) for n in names}
        try:
            ok = any(eval_condition(c, truth) for c in conds)
        except NotImplementedError as e:
            raise SynthError(f"unsupported condition: {e}")
        except ValueError as e:
            raise SynthError(f"invalid condition: {e}")
        if ok:
            found = True
            yield list(chosen)
    if not found:
        raise SynthError("no simple selection set satisfies the condition")


def satisfying_selections(det: dict) -> list[str]:
    return next(iter_satisfying(det))


# ---------------------------------------------------------------- constraints
def _constraints(sel_map: dict):
    """-> list of (field, op, patterns, is_all). op 'null' means: the field must be absent."""
    out = []
    for key, expected in sel_map.items():
        field, *mods = key.split("|")
        unknown = set(mods) - SUPPORTED_MODIFIERS
        if unknown:
            raise SynthError(f"unsupported modifier(s): {sorted(unknown)}")
        if isinstance(expected, list) and any(e is None for e in expected):
            raise SynthError("null inside a value list is not supported yet")
        if expected is None:
            out.append((field, "null", [], False))
            continue
        pats = [str(p) for p in (expected if isinstance(expected, list) else [expected])]
        op = ("contains" if "contains" in mods else "startswith" if "startswith" in mods
              else "endswith" if "endswith" in mods else "equals")
        out.append((field, op, pats, "all" in mods))
    return out


def _alternatives(sel, prefer: str):
    """All alternatives of a selection (one per map of a list), those using `prefer` first."""
    if isinstance(sel, list):
        if not sel or not all(isinstance(m, dict) for m in sel):
            raise SynthError("keyword selection (not supported yet)")
        maps = sel
    elif isinstance(sel, dict):
        maps = [sel]
    else:
        raise SynthError("keyword selection (not supported yet)")
    alts, first_error = [], None
    for m in maps:
        try:
            alts.append(_constraints(m))
        except SynthError as e:
            first_error = first_error or e
    if not alts:
        raise first_error
    alts.sort(key=lambda a: not any(c[0] == prefer and c[1] != "null" for c in a))
    return alts


def _mentions(det: dict, field: str) -> bool:
    for name, sel in det.items():
        if name in ("condition", "timeframe"):
            continue
        for m in (sel if isinstance(sel, list) else [sel]):
            if isinstance(m, dict) and any(k.split("|")[0] == field for k in m):
                return True
    return False


def _per_field_variants(det: dict, chosen: list[str], prefer: str):
    all_alts = [_alternatives(det[n], prefer) for n in chosen]
    for alt_idx in product(*[range(len(a)) for a in all_alts]):
        constraints = [c for a, i in zip(all_alts, alt_idx) for c in a[i]]
        ranges = [range(len(c[2])) if (not c[3] and len(c[2]) > 1) else range(1) for c in constraints]
        for pat_idx in product(*ranges):
            per_field: dict[str, list] = {}
            for (field, op, pats, is_all), k in zip(constraints, pat_idx):
                per_field.setdefault(field, []).append((op, pats if is_all else pats[k:k + 1]))
            yield per_field


# ---------------------------------------------------------------- value building
def _build(items) -> str:
    def collect(wanted):
        return [p for op, ps in items for p in ps if op == wanted]

    eq, starts, ends, cont = collect("equals"), collect("startswith"), collect("endswith"), collect("contains")
    if eq:
        if len(set(eq)) > 1:
            raise SynthError("conflicting equality constraints on one field")
        return literal_value(eq[0])
    if len(set(starts)) > 1 or len(set(ends)) > 1:
        raise SynthError("conflicting startswith/endswith constraints on one field")
    pieces = [literal_value(x) for x in starts[:1] + list(dict.fromkeys(cont)) + ends[:1]]
    value = ""
    for piece in pieces:
        glue = "" if (not value or piece[:1] in ("\\", ".")) else " "
        value += glue + piece
    return value


def _falsify_null_filters(det: dict, chosen: list[str], event: dict) -> None:
    """A filter like `Field: null` is true when the field is absent. Give such fields a filler value."""
    for name, sel in det.items():
        if name in ("condition", "timeframe") or name in chosen:
            continue
        try:
            if not _selection_matches(sel, event):
                continue
        except NotImplementedError:
            continue
        for m in (sel if isinstance(sel, list) else [sel]):
            if isinstance(m, dict):
                for key, expected in m.items():
                    field = key.split("|")[0]
                    if expected is None and field not in event:
                        event[field] = "x"


# ---------------------------------------------------------------- public API
def _program_name(event: dict) -> str:
    img = event.get("Image")
    if img:
        base = re.split(r"[\\/]", str(img))[-1]
        if base:
            return base
    return str(event.get("OriginalFileName") or "app.exe")


def _with_program(event: dict) -> dict | None:
    """Real command lines start with the program name; the rule's patterns usually do not."""
    cmd = event.get("CommandLine")
    if not cmd:
        return None
    return {**event, "CommandLine": f"{_program_name(event)} {cmd}"}


def synthesize_ex(rule: dict, verify: bool = True, prefer_field: str = "CommandLine"):
    """Return (event, positive_fields). positive_fields excludes filler values."""
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SynthError("no detection/condition")
    mentions = _mentions(det, prefer_field)
    best, first_error = None, None
    for chosen in islice(iter_satisfying(det), MAX_SELECTION_SETS):
        for per_field in islice(_per_field_variants(det, chosen, prefer_field), MAX_CANDIDATES):
            try:
                event = {f: _build(items) for f, items in per_field.items()
                         if any(op != "null" for op, _ in items)}
            except SynthError as e:
                first_error = first_error or e
                continue
            positive = set(event)
            _falsify_null_filters(det, chosen, event)
            variants = [event]
            prefixed = _with_program(event)
            if prefixed:
                variants.insert(0, prefixed)  # preferred: starts with the program name
            if not verify:
                return variants[0], positive
            good = None
            for ev in variants:
                try:
                    if matches(rule, ev):
                        good = ev
                        break
                except NotImplementedError as e:
                    raise SynthError(f"unsupported feature: {e}")
            if good is None:
                continue
            if prefer_field in positive or not mentions:
                return good, positive
            best = best or (good, positive)
    if best:
        return best
    raise first_error or SynthError("synthesized event does not satisfy the rule")


def synthesize(rule: dict, verify: bool = True) -> dict:
    return synthesize_ex(rule, verify)[0]
