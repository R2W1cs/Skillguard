"""Analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from skillguard.models.finding import Finding
from skillguard.models.skill import Skill
from skillguard.rules.registry import all_rules


class Analyzer(ABC):
    name: str

    @abstractmethod
    def analyze(self, skill: Skill, disabled: list[str] | None = None) -> list[Finding]:
        raise NotImplementedError


class RuleAnalyzer(Analyzer):
    """Generic analyzer that executes a filtered set of rules."""

    def __init__(self, name: str, rule_ids: set[str] | None = None) -> None:
        self.name = name
        self.rule_ids = rule_ids

    def analyze(self, skill: Skill, disabled: list[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in all_rules(disabled):
            if self.rule_ids is not None and rule.meta.id not in self.rule_ids:
                continue
            findings.extend(rule.check(skill))
        return findings


def run_all_analyzers(
    skill: Skill,
    analyzers: list[Analyzer],
    disabled: list[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for analyzer in analyzers:
        findings.extend(analyzer.analyze(skill, disabled=disabled))
    return findings
