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


_RUN = re.compile(r"^([-/]?)([A-Za-z]{4,})")


def _insert_in_token(tok: str, ins: str):
    m = _RUN.match(tok)
    if not m:
        return None
    pos = len(m.group(1)) + len(m.group(2)) // 2
    return tok[:pos] + ins + tok[pos:]


def _per_token(cmd: str, ins: str, name: str, assumption: str) -> list[Mutation]:
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        new = _insert_in_token(tok, ins)
        if new is None:
            continue
        value = " ".join(toks[:i] + [new] + toks[i + 1 :])
        out.append(Mutation(name, f"token {i} ({tok})", value, assumption))
    return out


def quote_split(cmd: str) -> list[Mutation]:
    # h""ttp is parsed back to http by the Windows argument parser.
    return _per_token(cmd, '""', "quote_split", ARGV)


def space_padding(cmd: str) -> list[Mutation]:
    value = re.sub(r" +", "  ", cmd)
    return [Mutation("space_padding", "double spaces", value, ARGV)] if value != cmd else []


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


MUTATORS = [quote_split, space_padding, caret_insert, option_prefix_swap]


def generate(cmd: str, assumptions=(ARGV,)) -> list[Mutation]:
    allowed = set(assumptions)
    return [m for fn in MUTATORS for m in fn(cmd) if m.assumption in allowed]
