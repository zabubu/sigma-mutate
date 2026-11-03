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


_NO_INSERT = set('\\"^&|<>%! \t')


def _boundaries(tok: str) -> list[tuple[str, int]]:
    """Insertion points between two ordinary ASCII characters: first, middle and last.

    Never next to a backslash (a backslash before a quote changes its meaning in Windows
    argument parsing), a quote, whitespace or a cmd.exe metacharacter; tokens that already
    contain a quote are left alone.
    """
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
    """`first_token`: assumption to use for token 0 (the program name), if different."""
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
    """The same insertion in EVERY argument at once (a pattern may occur in several tokens)."""
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
    # h""ttp is parsed back to http by the Windows argument parser. The program name (token 0)
    # is parsed by CreateProcess, which does not strip inner quotes: only cmd.exe does.
    return (_per_token(cmd, '""', "quote_split", ARGV, first_token=CMD)
            + _all_arguments(cmd, '""', "quote_split", ARGV))


def quote_wrap(cmd: str) -> list[Mutation]:
    # "-urlcache" is parsed back to -urlcache; it breaks rules that expect ' -urlcache '.
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


# Evidence from scripts/validate_mutators.py on a real Windows host (variants gave the same exit code and
# output as the original): quote_split / quote_wrap on arguments, whitespace tweaks, quote_wrap on the
# program name, and (through cmd.exe) caret_insert and quote_split on the program name.
VALIDATED_PROGRAMS = {"certutil.exe", "whoami.exe", "reg.exe", "findstr.exe", "sort.exe",
                      "powershell.exe", "curl.exe", "where.exe"}

# Programs that interpret their own command line instead of using standard argument parsing.
# Evidence: in `cmd.exe /c ty""pe file` the command is not found, and `echo he""llo` prints the quotes.
# Candidates still to validate: rundll32, msiexec, mshta, wscript, cscript, regsvr32.
SELF_PARSING = {"cmd.exe"}

MUTATORS = [quote_split, quote_wrap, space_padding, tab_separator, caret_insert, option_prefix_swap]

# Whitespace-only tweaks: they only break rules whose patterns contain spaces.
TRIVIAL = {"space_padding", "tab_separator"}


def program_of(cmd: str) -> str:
    """Lower-case file name of the program (first token), e.g. 'certutil.exe'."""
    first = cmd.strip().split(" ")[0].strip('"').replace("\\", "/")
    name = first.rsplit("/", 1)[-1].lower()
    return name if "." in name else name + ".exe"


def status_for(prog: str | None) -> str:
    if not prog or prog.lower() == "app.exe":  # placeholder used when the rule names no program
        return "unspecified"
    prog = prog.lower()
    if prog in SELF_PARSING:
        return "self-parsing"
    return "validated" if prog in VALIDATED_PROGRAMS else "unvalidated"


def program_status(cmd: str) -> str:
    return status_for(program_of(cmd))


def generate(cmd: str, assumptions=(ARGV,)) -> list[Mutation]:
    """Variants of a command line. For self-parsing programs (cmd.exe), quote mutations of the
    arguments are only valid command by command, so they are filed under 'program'."""
    allowed = set(assumptions)
    self_parsing = program_of(cmd) in SELF_PARSING
    out = []
    for fn in MUTATORS:
        for m in fn(cmd):
            if (self_parsing and m.assumption == ARGV and m.mutator in ("quote_split", "quote_wrap")
                    and not m.label.startswith("token 0")):
                m = Mutation(m.mutator, m.label, m.value, PROGRAM)
            if m.assumption in allowed:
                out.append(m)
    return out
