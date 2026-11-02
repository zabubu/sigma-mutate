"""Mutators: rewrite a command line so it does the same thing, written differently.

Every mutator declares the assumption under which the variant is semantically
equivalent. Without this, a "surviving evasion" would be meaningless:
  argv     -> same result after standard Windows argument parsing (CommandLineToArgvW)
  cmd.exe  -> only equivalent if the command is interpreted by cmd.exe
  program  -> depends on the target program (e.g. it accepts both '-' and '/')
Default is 'argv' only (highest confidence); the others are opt-in.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ARGV, CMD, PROGRAM = "argv", "cmd.exe", "program"


@dataclass(frozen=True)
class Mutation:
    mutator: str
    label: str
    value: str
    assumption: str


def _boundaries(tok: str) -> list[tuple[str, int]]:
    """Insertion points between two ASCII alphanumerics: first, middle and last.

    Never right after a backslash (a backslash before a quote changes its meaning in
    Windows argument parsing) and never next to punctuation.
    """
    ok = [i for i in range(1, len(tok))
          if tok[i - 1].isascii() and tok[i - 1].isalnum() and tok[i].isascii() and tok[i].isalnum()]
    if not ok:
        return []
    picks = {"first": ok[0], "middle": min(ok, key=lambda i: abs(i - len(tok) // 2)), "last": ok[-1]}
    seen, out = set(), []
    for name, i in picks.items():
        if i not in seen:
            seen.add(i)
            out.append((name, i))
    return out


def _per_token(cmd: str, ins: str, name: str, assumption: str) -> list[Mutation]:
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        for where, pos in _boundaries(tok):
            new = tok[:pos] + ins + tok[pos:]
            value = " ".join(toks[:i] + [new] + toks[i + 1 :])
            out.append(Mutation(name, f"token {i} ({tok}) {where}", value, assumption))
    return out


def quote_split(cmd: str) -> list[Mutation]:
    # h""ttp is parsed back to http by the Windows argument parser.
    return _per_token(cmd, '""', "quote_split", ARGV)


def quote_wrap(cmd: str) -> list[Mutation]:
    # "-urlcache" is parsed back to -urlcache; it breaks rules that expect ' -urlcache '.
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        if tok and '"' not in tok and "\\" not in tok[-1:]:
            value = " ".join(toks[:i] + ['"' + tok + '"'] + toks[i + 1 :])
            out.append(Mutation("quote_wrap", f"token {i} ({tok})", value, ARGV))
    return out


def space_padding(cmd: str) -> list[Mutation]:
    value = re.sub(r" +", "  ", cmd)
    return [Mutation("space_padding", "double spaces", value, ARGV)] if value != cmd else []


def tab_separator(cmd: str) -> list[Mutation]:
    # the Windows argument parser treats a tab like a space
    value = cmd.replace(" ", "\t")
    return [Mutation("tab_separator", "tabs instead of spaces", value, ARGV)] if value != cmd else []


def caret_insert(cmd: str) -> list[Mutation]:
    return _per_token(cmd, "^", "caret_insert", CMD)


def option_prefix_swap(cmd: str) -> list[Mutation]:
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        if len(tok) > 1 and tok[0] == "-" and tok[1].isalpha():
            value = " ".join(toks[:i] + ["/" + tok[1:]] + toks[i + 1 :])
            out.append(Mutation("option_prefix_swap", f"token {i} ({tok})", value, PROGRAM))
    return out


MUTATORS = [quote_split, quote_wrap, space_padding, tab_separator, caret_insert, option_prefix_swap]

# Whitespace-only tweaks: they only break rules whose patterns contain spaces.
TRIVIAL = {"space_padding", "tab_separator"}


def generate(cmd: str, assumptions=(ARGV,)) -> list[Mutation]:
    allowed = set(assumptions)
    return [m for fn in MUTATORS for m in fn(cmd) if m.assumption in allowed]
