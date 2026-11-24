"""Dangerous shell and command injection rules."""

from __future__ import annotations

import re

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import (
    Match,
    RegexRule,
    Rule,
    RuleMeta,
    is_educational_context,
    iter_text_files,
    line_of,
    snippet_at,
)


class DangerousShellRule(RegexRule):
    meta = RuleMeta(
        id="SG-SHELL-001",
        name="Dangerous shell command",
        description="Detects high-risk shell commands such as rm -rf /, mkfs, dd, fork bombs, etc.",
        severity=Severity.CRITICAL,
        category=Category.SHELL,
        remediation="Remove destructive commands; document safe alternatives and require explicit user approval.",
        tags=("shell", "destructive"),
    )
    skip_educational = True
    default_confidence = Confidence.HIGH
    patterns = [
        re.compile(r"(?i)\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*[\"']?/(?:\s|$|[\"'])"),
        re.compile(r"(?i)\brm\s+-rf\s+[\"']?~"),
        re.compile(r"(?i)\bmkfs(\.\w+)?\b"),
        re.compile(r"(?i)\bdd\s+if=.+\s+of=/dev/"),
        re.compile(r"(?i):\(\)\s*\{\s*:\|:&\s*\}\s*;:"),  # fork bomb
        re.compile(r"(?i)\bcurl\b.+\|\s*(?:ba)?sh\b"),
        re.compile(r"(?i)\bwget\b.+\|\s*(?:ba)?sh\b"),
        re.compile(r"(?i)\bchmod\s+(-R\s+)?777\b"),
    ]


class CommandInjectionRule(RegexRule):
    meta = RuleMeta(
        id="SG-SHELL-002",
        name="Command injection pattern",
        description="Detects shell invocation patterns that concatenate untrusted input into commands.",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        remediation="Avoid shell=True / os.system with concatenated input; use argument lists and sanitization.",
        tags=("injection", "shell"),
    )
    skip_educational = True
    default_confidence = Confidence.MEDIUM
    patterns = [
        re.compile(r"(?i)\bos\.system\s*\("),
        re.compile(r"(?i)\bsubprocess\.[a-z]+\([^)]*shell\s*=\s*True"),
        re.compile(r"(?i)\beval\s*\("),
        re.compile(r"(?i)\bexec\s*\("),
        re.compile(r"(?i)\bchild_process\.exec\s*\("),
        re.compile(r"(?i)`[^`]*\$\{[^}]+\}[^`]*`"),
        re.compile(r"(?i)\$\([^)]*\$\{?\w+"),
    ]


class DownloadExecuteRule(Rule):
    meta = RuleMeta(
        id="SG-SHELL-003",
        name="Download-and-execute pattern",
        description="Detects patterns that download remote content and execute it immediately.",
        severity=Severity.CRITICAL,
        category=Category.SUPPLY_CHAIN,
        remediation="Do not pipe remote scripts to a shell. Pin, verify checksums, and review before execution.",
        tags=("supply-chain", "download"),
    )

    _patterns = [
        re.compile(r"(?i)(curl|wget|Invoke-WebRequest|iwr).{0,80}\|\s*(ba)?sh"),
        re.compile(r"(?i)(curl|wget).{0,80}\|\s*python"),
        re.compile(r"(?i)iwr\s+.+\|\s*iex"),
        re.compile(r"(?i)invoke-expression\s*\("),
        re.compile(r"(?i)requests\.get\([^)]+\).{0,80}exec\("),
        re.compile(r"(?i)exec\s*\(\s*requests\.get\("),
        re.compile(r"(?i)exec\s*\(\s*[^)]*requests\.get\([^)]*\)\.text"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for pat in self._patterns:
                for m in pat.finditer(content):
                    if is_educational_context(content, m.start()) and sf.relative_path.endswith(
                        ".md"
                    ):
                        continue
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=sf.relative_path,
                                line=line_of(content, m.start()),
                                snippet=snippet_at(content, m.start()),
                                confidence=Confidence.HIGH,
                            )
                        )
                    )
        return findings


class DynamicCodeExecRule(RegexRule):
    meta = RuleMeta(
        id="SG-SHELL-004",
        name="Suspicious dynamic code execution",
        description="Detects dynamic evaluation of strings as code (eval/exec/Function/compile).",
        severity=Severity.HIGH,
        category=Category.DYNAMIC_EXEC,
        remediation="Avoid dynamic code execution on untrusted input.",
        tags=("dynamic-exec",),
    )
    skip_educational = True
    default_confidence = Confidence.MEDIUM
    patterns = [
        re.compile(r"(?i)\bcompile\s*\(.+,\s*['\"]<string>['\"]"),
        re.compile(r"(?i)\bFunction\s*\("),
        re.compile(r"(?i)\bnew\s+Function\s*\("),
        re.compile(r"(?i)\b__import__\s*\(\s*['\"]os['\"]"),
        re.compile(r"(?i)\bgetattr\s*\([^,]+,\s*input\("),
    ]


RULES = [
    DangerousShellRule(),
    CommandInjectionRule(),
    DownloadExecuteRule(),
    DynamicCodeExecRule(),
]
