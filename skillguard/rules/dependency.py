"""Dependency and installation risk rules."""

from __future__ import annotations

import re

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import (
    Match,
    RegexRule,
    Rule,
    RuleMeta,
    iter_text_files,
    line_of,
    snippet_at,
)


class DependencyInstallRiskRule(Rule):
    meta = RuleMeta(
        id="SG-DEP-001",
        name="Risky dependency or installation command",
        description=(
            "Detects unpinned installs, pip/npm from remote URLs, or install scripts with elevated risk."
        ),
        severity=Severity.MEDIUM,
        category=Category.DEPENDENCY,
        remediation="Pin versions, prefer lockfiles, and avoid installing packages directly from arbitrary URLs.",
        tags=("dependency", "supply-chain"),
    )

    patterns = [
        re.compile(r"(?i)\bpip\s+install\s+[^#\n]*https?://"),
        re.compile(r"(?i)\bpip\s+install\s+[^\n]*--break-system-packages"),
        re.compile(r"(?i)\bnpm\s+install\s+-g\b"),
        re.compile(r"(?i)\bnpm\s+install\s+[^#\n]*https?://"),
        re.compile(r"(?i)\bcurl\b.+\|\s*pip\s+install"),
        re.compile(r"(?i)\bchmod\s+\+x\b.+\n.*\./"),
        re.compile(r"(?i)\binstall\s+-g\s+[a-z0-9_-]+@latest\b"),
        re.compile(r"(?i)\bpostinstall\b.+\b(curl|wget|node\s+-e|python)"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for pat in self.patterns:
                for m in pat.finditer(content):
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=sf.relative_path,
                                line=line_of(content, m.start()),
                                snippet=snippet_at(content, m.start()),
                                confidence=Confidence.MEDIUM,
                            )
                        )
                    )
        return findings


class UnexpectedBinaryRule(RegexRule):
    meta = RuleMeta(
        id="SG-DEP-002",
        name="Unexpected executable or binary artifact",
        description="Flags unexpected binary/executable files shipped inside a skill package.",
        severity=Severity.MEDIUM,
        category=Category.SUPPLY_CHAIN,
        remediation="Avoid shipping opaque binaries; prefer auditable source scripts.",
        tags=("supply-chain", "binary"),
    )
    # This rule uses check override below
    patterns = []
    skip_educational = False

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in skill.files:
            name = sf.relative_path.lower()
            suspicious_ext = name.endswith(
                (".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".pyc")
            )
            if sf.binary or suspicious_ext:
                findings.append(
                    self.finding_from_match(
                        Match(
                            file_path=sf.relative_path,
                            line=None,
                            snippet=f"Binary or executable-like file ({sf.size} bytes)",
                            confidence=Confidence.MEDIUM,
                        )
                    )
                )
        return findings


RULES = [
    DependencyInstallRiskRule(),
    UnexpectedBinaryRule(),
]
