"""Synthesize a minimal true-positive event from a Sigma rule.

SigmaHQ rules ship without matching events, so we build one from the rule itself:
pick a set of selections that satisfies the condition, then build a value for each
constrained field. The result is verified with the matcher before being returned.

Caveat: synthesized command lines are minimal (they contain what the rule asks for,
not a realistic attack), so scores measure the rule's fragility on its own patterns.
"""
from __future__ import annotations

from itertools import combinations

from .matcher import SUPPORTED_MODIFIERS, eval_condition, literal_value, matches


class SynthError(Exception):
    """The rule cannot be turned into an event (reason in the message)."""


def _candidates(names):
    """Small selections sets first, then 'everything' and 'everything but one'."""
    for k in range(0, min(len(names), 3) + 1):
        yield from combinations(names, k)
    yield tuple(names)
    for skipped in names:
        yield tuple(n for n in names if n != skipped)


def _satisfying_selections(det: dict) -> list[str]:
    names = [k for k in det if k not in ("condition", "timeframe")]
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    for chosen in _candidates(names):
        truth = {n: (n in chosen) for n in names}
        try:
            if any(eval_condition(c, truth) for c in conds):
                return list(chosen)
        except NotImplementedError as e:
            raise SynthError(f"unsupported condition: {e}")
        except ValueError as e:
            raise SynthError(f"invalid condition: {e}")
    raise SynthError("no simple selection set satisfies the condition")


def _constraints(sel):
    if isinstance(sel, list):
        if not sel or not all(isinstance(s, dict) for s in sel):
            raise SynthError("keyword selection (not supported yet)")
        sel = sel[0]
    if not isinstance(sel, dict):
        raise SynthError("keyword selection (not supported yet)")
    out = []
    for key, expected in sel.items():
        field, *mods = key.split("|")
        unknown = set(mods) - SUPPORTED_MODIFIERS
        if unknown:
            raise SynthError(f"unsupported modifier(s): {sorted(unknown)}")
        if expected is None:
            raise SynthError("null value (field absence) not supported yet")
        pats = [str(p) for p in (expected if isinstance(expected, list) else [expected])]
        op = ("contains" if "contains" in mods else "startswith" if "startswith" in mods
              else "endswith" if "endswith" in mods else "equals")
        out.append((field, op, pats if "all" in mods else pats[:1]))
    return out


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


def synthesize(rule: dict) -> dict:
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SynthError("no detection/condition")
    per_field: dict[str, list] = {}
    for name in _satisfying_selections(det):
        for field, op, pats in _constraints(det[name]):
            per_field.setdefault(field, []).append((op, pats))
    event = {f: _build(items) for f, items in per_field.items()}
    try:
        ok = matches(rule, event)
    except NotImplementedError as e:
        raise SynthError(f"unsupported feature: {e}")
    if not ok:
        raise SynthError("synthesized event does not satisfy the rule")
    return event
