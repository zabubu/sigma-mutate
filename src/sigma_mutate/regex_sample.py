"""Build a short string that a regular expression matches.

Walks the tree produced by Python's own regex parser and takes the cheapest path:
first branch, minimum repetitions, first acceptable character of a class.
"""
from __future__ import annotations

import string

try:
    from re import _parser as sre_parse  # Python 3.11+
except ImportError:  # pragma: no cover
    import sre_parse  # type: ignore

_PREFERRED = "a0 xA-_./:\\" + string.ascii_letters + string.digits + string.punctuation


class Unsupported(ValueError):
    pass


def _category(ch: str, cat: str) -> bool:
    if cat.endswith("NOT_DIGIT"):
        return not ch.isdigit()
    if cat.endswith("DIGIT"):
        return ch.isdigit()
    if cat.endswith("NOT_SPACE"):
        return not ch.isspace()
    if cat.endswith("SPACE"):
        return ch.isspace()
    if cat.endswith("NOT_WORD"):
        return not (ch.isalnum() or ch == "_")
    if cat.endswith("WORD"):
        return ch.isalnum() or ch == "_"
    raise Unsupported(f"character category {cat}")


def _in_class(ch: str, items) -> bool:
    negate, hit = False, False
    for op, av in items:
        name = op.name
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL":
            hit = hit or ord(ch) == av
        elif name == "RANGE":
            hit = hit or av[0] <= ord(ch) <= av[1]
        elif name == "CATEGORY":
            hit = hit or _category(ch, av.name)
        else:
            raise Unsupported(f"character class item {name}")
    return hit != negate


def _gen(seq) -> str:
    out = []
    for op, av in seq:
        name = op.name
        if name == "LITERAL":
            out.append(chr(av))
        elif name == "NOT_LITERAL":
            out.append("x" if chr(av) != "x" else "y")
        elif name == "ANY":
            out.append("x")
        elif name == "IN":
            ch = next((c for c in _PREFERRED if _in_class(c, av)), None)
            if ch is None:
                raise Unsupported("empty character class")
            out.append(ch)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo, _hi, sub = av
            out.append(_gen(sub) * lo)
        elif name == "SUBPATTERN":
            out.append(_gen(av[-1]))
        elif name == "ATOMIC_GROUP":
            out.append(_gen(av))
        elif name == "BRANCH":
            out.append(_gen(av[1][0]))
        elif name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue  # anchors and lookarounds: the caller checks the result anyway
        else:
            raise Unsupported(f"regex construct {name}")
    return "".join(out)


def sample(pattern: str, flags: int = 0) -> str:
    return _gen(sre_parse.parse(pattern, flags))


def anchored(pattern: str) -> tuple[bool, bool]:
    """(anchored at start, anchored at end), looking at the top level only."""
    tree = list(sre_parse.parse(pattern))
    def is_at(node, names):
        return node[0].name == "AT" and node[1].name in names
    start = bool(tree) and is_at(tree[0], ("AT_BEGINNING", "AT_BEGINNING_STRING"))
    end = bool(tree) and is_at(tree[-1], ("AT_END", "AT_END_STRING"))
    return start, end
