"""Build a minimal true-positive event from a Sigma rule.

SigmaHQ rules ship without sample events, so we derive one from the rule: pick selections that
make the condition true, one value per constrained field, then check the result with the matcher.
The command lines it produces only contain what the rule asks for, not a realistic attack.
"""
from __future__ import annotations

import re
from itertools import combinations, islice, product

from . import regex_sample
from .matcher import (_selection_matches, base64_variants, check_modifiers, escape, eval_condition,
                      literal_value, matches, operator, user_regex)

MAX_SELECTION_SETS = 5
MAX_CANDIDATES = 60  # value combinations tried per selection set


class SynthError(Exception):
    pass


def _candidates(names):
    # small sets first, then everything and everything-but-one
    seen = set()
    for k in range(0, min(len(names), 3) + 1):
        for c in combinations(names, k):
            seen.add(c)
            yield c
    for c in [tuple(names)] + [tuple(n for n in names if n != s) for s in names]:
        if c not in seen:
            seen.add(c)
            yield c


def _is_minimal(chosen, names, conds) -> bool:
    # With both sides of an `A or B` true, evading A would go unnoticed because B still fires.
    for n in chosen:
        truth = {m: (m in chosen and m != n) for m in names}
        try:
            if any(eval_condition(c, truth) for c in conds):
                return False
        except (NotImplementedError, ValueError):
            pass
    return True


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
        if ok and _is_minimal(chosen, names, conds):
            found = True
            yield list(chosen)
    if not found:
        raise SynthError("no simple selection set satisfies the condition")


def satisfying_selections(det: dict) -> list[str]:
    return next(iter_satisfying(det))


def _regex_constraint(pats, mods):
    out = []
    for p in pats:
        try:
            compiled = user_regex(p, mods)
            value = regex_sample.sample(p, compiled.flags)
            start, end = regex_sample.anchored(p)
        except (regex_sample.Unsupported, re.error, NotImplementedError) as e:
            raise SynthError(f"cannot build a value for regex: {e}")
        if not compiled.search(value):
            raise SynthError(f"cannot build a value for regex {p!r}")
        op = "equals" if start and end else "startswith" if start else "endswith" if end else "contains"
        out.append((op, escape(value)))
    return out


def _constraints(sel_map: dict):
    """-> list of (field, op, patterns, is_all). op 'null' means the field must be absent."""
    out = []
    for key, expected in sel_map.items():
        field, *mods = key.split("|")
        try:
            check_modifiers(mods)
        except NotImplementedError as e:
            raise SynthError(str(e))
        if isinstance(expected, list) and any(e is None for e in expected):
            raise SynthError("null inside a value list is not supported yet")
        if expected is None:
            out.append((field, "null", [], False))
            continue
        pats = [str(p) for p in (expected if isinstance(expected, list) else [expected])]
        if "re" in mods:
            built = _regex_constraint(pats, mods)
            if "all" in mods:
                out.extend((field, op, [v], True) for op, v in built)
            else:
                # one regex is enough; prefer an unanchored one, it combines more easily
                built.sort(key=lambda b: b[0] != "contains")
                op = built[0][0]
                out.append((field, op, [v for o, v in built if o == op], False))
            continue
        if "base64" in mods or "base64offset" in mods:
            try:
                pats = [escape(base64_variants(p, "base64offset" in mods)[0]) for p in pats]
            except NotImplementedError as e:
                raise SynthError(str(e))
        out.append((field, operator(mods), pats, "all" in mods))
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
    # `Field: null` filters fire when the field is absent, so give those fields a dummy value.
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


def _program_hint(det: dict) -> str | None:
    # program name from Image / OriginalFileName in a selection that is not a filter
    for name, sel in det.items():
        if name in ("condition", "timeframe") or name.lower().startswith("filter"):
            continue
        for m in (sel if isinstance(sel, list) else [sel]):
            if not isinstance(m, dict):
                continue
            for key, expected in m.items():
                if key.split("|")[0] in ("Image", "OriginalFileName"):
                    for pat in (expected if isinstance(expected, list) else [expected]):
                        if isinstance(pat, str):
                            base = re.split(r"[\\/]", literal_value(pat))[-1]
                            if base.lower().endswith(".exe"):
                                return base
    return None


def _program_name(event: dict, hint: str | None) -> str:
    img = event.get("Image")
    if img:
        base = re.split(r"[\\/]", str(img))[-1]
        if base:
            return base
    return str(event.get("OriginalFileName") or hint or "app.exe")


def _with_program(event: dict, hint: str | None) -> dict | None:
    # real command lines start with the program name, the rule's patterns usually don't
    cmd = event.get("CommandLine")
    if not cmd:
        return None
    name = _program_name(event, hint)
    stem = name.lower().rsplit(".", 1)[0]
    if name != "app.exe" and stem and stem in cmd.split(" ")[0].lower():
        return None  # already there
    return {**event, "CommandLine": f"{name} {cmd}"}


def rule_program(rule: dict, event: dict) -> str | None:
    """Program the rule targets, or None if it names none."""
    name = _program_name(event, _program_hint(rule.get("detection") or {}))
    return None if name == "app.exe" else name


def field_independent(rule: dict, field: str = "CommandLine") -> bool:
    """True if the rule can also fire without looking at `field` (e.g. on the binary name alone),
    in which case evading `field` does not evade the rule."""
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        return False
    try:
        for chosen in islice(iter_satisfying(det), 20):
            ok = True
            for n in chosen:
                alts = _alternatives(det[n], field)
                if not any(not any(c[0] == field and c[1] != "null" for c in alt) for alt in alts):
                    ok = False
                    break
            if ok:
                return True
    except SynthError:
        return False
    return False


def synthesize_ex(rule: dict, verify: bool = True, prefer_field: str = "CommandLine"):
    """Return (event, fields set to satisfy the rule, i.e. without the dummy values)."""
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SynthError("no detection/condition")
    mentions = _mentions(det, prefer_field)
    hint = _program_hint(det)
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
            prefixed = _with_program(event, hint)
            if prefixed:
                variants.insert(0, prefixed)
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
