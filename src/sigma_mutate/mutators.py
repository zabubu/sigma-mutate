"""Rewrite a command line so that it does the same thing but reads differently.

Each variant carries the assumption it relies on: "argv" (standard Windows argument parsing,
CommandLineToArgvW), "cmd.exe" (only true when cmd.exe interprets the line) or "program"
(depends on the program, e.g. accepting /x for -x). Only argv is used by default.
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


_NO_INSERT = set('\\"^&|<>%! \t')


def _boundaries(tok: str) -> list[tuple[str, int]]:
    # First, middle and last spot between two plain ASCII characters. Never next to a backslash
    # (\" means something else to the argument parser), a quote, whitespace or a cmd.exe
    # metacharacter, and tokens that already contain a quote are left alone.
    if '"' in tok:
        return []
    ok = [i for i in range(1, len(tok))
          if tok[i - 1].isascii() and tok[i].isascii()
          and tok[i - 1] not in _NO_INSERT and tok[i] not in _NO_INSERT]
    if not ok:
        return []
    picks = {"first": ok[0], "middle": min(ok, key=lambda i: abs(i - len(tok) // 2)), "last": ok[-1]}
    seen, out = set(), []
    for name, i in picks.items():
        if i not in seen:
            seen.add(i)
            out.append((name, i))
    return out


def _per_token(cmd: str, ins: str, name: str, assumption: str, first_token: str | None = None) -> list[Mutation]:
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        for where, pos in _boundaries(tok):
            new = tok[:pos] + ins + tok[pos:]
            value = " ".join(toks[:i] + [new] + toks[i + 1 :])
            out.append(Mutation(name, f"token {i} ({tok}) {where}", value,
                                first_token if (i == 0 and first_token) else assumption))
    return out


def _all_arguments(cmd: str, ins: str, name: str, assumption: str) -> list[Mutation]:
    # same insertion in every argument at once, for patterns that span several tokens
    toks = cmd.split(" ")
    out = []
    for where in ("first", "middle", "last"):
        new, hit = list(toks), 0
        for i in range(1, len(toks)):
            for w, pos in _boundaries(toks[i]):
                if w == where:
                    new[i] = toks[i][:pos] + ins + toks[i][pos:]
                    hit += 1
                    break
        if hit >= 2:
            out.append(Mutation(name, f"all arguments {where}", " ".join(new), assumption))
    return out


def quote_split(cmd: str) -> list[Mutation]:
    # h""ttp becomes http again once parsed. Not for the program name though: CreateProcess
    # keeps the quotes there, only cmd.exe removes them.
    return (_per_token(cmd, '""', "quote_split", ARGV, first_token=CMD)
            + _all_arguments(cmd, '""', "quote_split", ARGV))


def quote_wrap(cmd: str) -> list[Mutation]:
    # "-urlcache" parses back to -urlcache, and breaks patterns like ' -urlcache '.
    toks = cmd.split(" ")
    out = []
    for i, tok in enumerate(toks):
        if tok and '"' not in tok and "\\" not in tok[-1:]:
            value = " ".join(toks[:i] + ['"' + tok + '"'] + toks[i + 1 :])
            out.append(Mutation("quote_wrap", f"token {i} ({tok})", value, ARGV))
    eligible = [i for i, t in enumerate(toks) if t and '"' not in t and "\\" not in t[-1:]]
    if len(eligible) >= 2:
        wrapped = ['"' + t + '"' if i in eligible else t for i, t in enumerate(toks)]
        out.append(Mutation("quote_wrap", "all tokens", " ".join(wrapped), ARGV))
    return out


def space_padding(cmd: str) -> list[Mutation]:
    value = re.sub(r" +", "  ", cmd)
    return [Mutation("space_padding", "double spaces", value, ARGV)] if value != cmd else []


def tab_separator(cmd: str) -> list[Mutation]:
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


# Programs for which scripts/validate_mutators.py showed the variants behave like the original.
VALIDATED_PROGRAMS = {"certutil.exe", "whoami.exe", "reg.exe", "findstr.exe", "sort.exe",
                      "powershell.exe", "curl.exe", "where.exe",
                      "bitsadmin.exe", "netsh.exe", "sc.exe", "net.exe", "wmic.exe"}

# Found on a real host: net.exe and wmic.exe don't split on tabs, wmic.exe keeps inner quotes.
# schtasks.exe is left out of the validated list, its first test run gave unstable output.
MUTATOR_EXCEPTIONS = {"net.exe": {"tab_separator"}, "wmic.exe": {"quote_split", "tab_separator"}}

# Programs that parse their own command line: `cmd.exe /c ty""pe file` fails, `echo he""llo`
# prints the quotes. rundll32, msiexec, mshta, wscript, cscript and regsvr32 still need checking.
SELF_PARSING = {"cmd.exe"}

MUTATORS = [quote_split, quote_wrap, space_padding, tab_separator, caret_insert, option_prefix_swap]

# whitespace only: these can only break patterns that contain spaces
TRIVIAL = {"space_padding", "tab_separator"}


def program_of(cmd: str) -> str:
    """'certutil.exe' for 'C:\\Windows\\System32\\CertUtil.exe -urlcache ...'."""
    first = cmd.strip().split(" ")[0].strip('"').replace("\\", "/")
    name = first.rsplit("/", 1)[-1].lower()
    return name if "." in name else name + ".exe"


def status_for(prog: str | None) -> str:
    if not prog or prog.lower() == "app.exe":  # app.exe: the synthesizer's placeholder
        return "unspecified"
    prog = prog.lower()
    if prog in SELF_PARSING:
        return "self-parsing"
    return "validated" if prog in VALIDATED_PROGRAMS else "unvalidated"


def program_status(cmd: str) -> str:
    return status_for(program_of(cmd))


def generate(cmd: str, assumptions=(ARGV,)) -> list[Mutation]:
    # Known exceptions and self-parsing programs downgrade the affected variants to "program".
    allowed = set(assumptions)
    prog = program_of(cmd)
    self_parsing = prog in SELF_PARSING
    excluded = MUTATOR_EXCEPTIONS.get(prog, set())
    out = []
    for fn in MUTATORS:
        for m in fn(cmd):
            if m.assumption == ARGV and m.mutator in excluded and not m.label.startswith("token 0"):
                m = Mutation(m.mutator, m.label, m.value, PROGRAM)
            if (self_parsing and m.assumption == ARGV and m.mutator in ("quote_split", "quote_wrap")
                    and not m.label.startswith("token 0")):
                m = Mutation(m.mutator, m.label, m.value, PROGRAM)
            if m.assumption in allowed:
                out.append(m)
    return out
