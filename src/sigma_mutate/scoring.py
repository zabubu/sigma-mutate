from __future__ import annotations

from dataclasses import dataclass, field

from .matcher import matches
from .mutators import ARGV, Mutation, generate


class BaselineError(ValueError):
    pass


@dataclass
class Result:
    mutation: Mutation
    detected: bool


@dataclass
class Report:
    title: str
    results: list[Result] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def detected(self) -> int:
        return sum(r.detected for r in self.results)

    @property
    def score(self) -> float:
        return 1.0 if self.total == 0 else self.detected / self.total

    @property
    def evasions(self) -> list[Result]:
        return [r for r in self.results if not r.detected]


def score_rule(rule: dict, event: dict, field_name: str = "CommandLine", assumptions=(ARGV,)) -> Report:
    if field_name not in event:
        raise ValueError(f"event has no field '{field_name}'")
    if not matches(rule, event):
        raise BaselineError("rule does not fire on the original event; use a true-positive event")
    report = Report(title=rule.get("title", "<untitled>"))
    for mutation in generate(str(event[field_name]), assumptions):
        mutated = {**event, field_name: mutation.value}
        report.results.append(Result(mutation, matches(rule, mutated)))
    return report
