"""Base rule interface for SkillGuard detectors."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field

from skillguard.models.finding import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from skillguard.models.skill import Skill, SkillFile


@dataclass(frozen=True)
class RuleMeta:
    id: str
    name: str
    description: str
    severity: Severity
    category: Category
    remediation: str
    tags: tuple[str, ...] = ()


@dataclass
class Match:
    file_path: str
    line: int | None
    snippet: str
    confidence: Confidence = Confidence.MEDIUM
    severity_override: Severity | None = None
    context: str | None = None
    extra_tags: list[str] = field(default_factory=list)


class Rule(ABC):
    """A detection rule. Subclass and implement ``check``."""

    meta: RuleMeta

    @abstractmethod
    def check(self, skill: Skill) -> list[Finding]:
        raise NotImplementedError

    def finding_from_match(self, match: Match) -> Finding:
        severity = match.severity_override or self.meta.severity
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.name,
            description=self.meta.description,
            severity=severity,
            confidence=match.confidence,
            category=self.meta.category,
            file_path=match.file_path,
            line=match.line,
            evidence=Evidence(
                snippet=match.snippet,
                line_start=match.line,
                line_end=match.line,
                context=match.context,
            ),
            remediation=self.meta.remediation,
            tags=list(self.meta.tags) + match.extra_tags,
        )


def iter_text_files(skill: Skill) -> Iterable[SkillFile]:
    for f in skill.files:
        if f.content is not None and not f.binary:
            yield f


def line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def snippet_at(content: str, index: int, length: int = 120) -> str:
    line_start = content.rfind("\n", 0, index) + 1
    line_end = content.find("\n", index)
    if line_end == -1:
        line_end = min(len(content), line_start + length)
    return content[line_start:line_end].strip()[:length]


def is_educational_context(content: str, match_start: int, window: int = 200) -> bool:
    """Heuristic: nearby words suggest docs/examples, not live instructions."""
    start = max(0, match_start - window)
    end = min(len(content), match_start + window)
    ctx = content[start:end].lower()
    markers = (
        "example",
        "for example",
        "do not",
        "don't",
        "never run",
        "avoid",
        "documentation",
        "warning:",
        "⚠️",
        "bad practice",
        "anti-pattern",
        "```",
        "demo only",
        "illustrative",
    )
    return any(m in ctx for m in markers)


class RegexRule(Rule):
    """Convenience rule that scans text files with one or more regexes."""

    patterns: list[re.Pattern[str]]
    skip_educational: bool = True
    default_confidence: Confidence = Confidence.MEDIUM
    target_kinds: set[str] | None = None  # None = all text

    def check(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for sf in iter_text_files(skill):
            if self.target_kinds and sf.kind.value not in self.target_kinds:
                continue
            content = sf.content or ""
            for pattern in self.patterns:
                for m in pattern.finditer(content):
                    if self.skip_educational and is_educational_context(content, m.start()):
                        # Downgrade rather than drop entirely for scripts; drop for markdown docs
                        if sf.relative_path.lower().endswith(".md"):
                            continue
                        conf = Confidence.LOW
                    else:
                        conf = self.default_confidence
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=sf.relative_path,
                                line=line_of(content, m.start()),
                                snippet=snippet_at(content, m.start()),
                                confidence=conf,
                            )
                        )
                    )
        return findings
