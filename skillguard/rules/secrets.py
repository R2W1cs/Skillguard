"""Secret and credential detection rules."""

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


class HardcodedApiKeyRule(RegexRule):
    meta = RuleMeta(
        id="SG-SECRET-001",
        name="Hardcoded API key or token",
        description="Detects hardcoded API keys, tokens, or bearer credentials in skill files.",
        severity=Severity.CRITICAL,
        category=Category.SECRETS,
        remediation="Remove secrets from the skill; load them from a secure secret store at runtime.",
        tags=("secrets", "credentials"),
    )
    skip_educational = True
    default_confidence = Confidence.HIGH
    patterns = [
        re.compile(r"(?i)\b(sk-[A-Za-z0-9]{20,})\b"),
        re.compile(r"(?i)\b(ghp_[A-Za-z0-9]{36,})\b"),
        re.compile(r"(?i)\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"),
        re.compile(
            r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)"
            r"\s*[=:]\s*['\"][^'\"]{12,}['\"]"
        ),
    ]
    _PLACEHOLDER = re.compile(
        r"(?i)(your[_-]?key|replace|example|placeholder|xxx+|changeme|dummy|not[_-]?a[_-]?real)"
    )

    def check(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for pattern in self.patterns:
                for m in pattern.finditer(content):
                    snippet = snippet_at(content, m.start())
                    if self._PLACEHOLDER.search(snippet) or self._PLACEHOLDER.search(m.group(0)):
                        continue
                    if (
                        self.skip_educational
                        and is_educational_context(content, m.start())
                        and sf.relative_path.lower().endswith(".md")
                    ):
                        continue
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=sf.relative_path,
                                line=line_of(content, m.start()),
                                snippet=snippet,
                                confidence=self.default_confidence,
                            )
                        )
                    )
        return findings


class PrivateKeyRule(RegexRule):
    meta = RuleMeta(
        id="SG-SECRET-002",
        name="Embedded private key",
        description="Detects PEM/OpenSSH private key material embedded in skill files.",
        severity=Severity.CRITICAL,
        category=Category.SECRETS,
        remediation="Never ship private keys inside skills. Use OS keychains or secret managers.",
        tags=("secrets", "private-key"),
    )
    skip_educational = False
    default_confidence = Confidence.HIGH
    patterns = [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ]


class EnvVarExposureRule(Rule):
    meta = RuleMeta(
        id="SG-SECRET-003",
        name="Environment variable secret exposure",
        description=(
            "Detects instructions or code that dump environment variables or print secret env vars."
        ),
        severity=Severity.HIGH,
        category=Category.CREDENTIALS,
        remediation="Avoid dumping process environments; request only least-privilege variables.",
        tags=("env", "credentials"),
    )

    _patterns = [
        re.compile(r"(?i)\bprintenv\b"),
        re.compile(r"(?i)\benv\s*\|\s*grep"),
        re.compile(r"(?i)os\.environ\b"),
        re.compile(r"(?i)process\.env\b"),
        re.compile(r"(?i)\$\{?(?:AWS|GITHUB|OPENAI|ANTHROPIC|SECRET|TOKEN|PASSWORD)[_A-Z0-9]*\}?"),
        re.compile(r"(?i)(dump|exfiltrate|send|upload).{0,40}(env|environment|secrets?)"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for pat in self._patterns:
                for m in pat.finditer(content):
                    snippet = snippet_at(content, m.start())
                    window = content[max(0, m.start() - 48) : m.start() + 48].lower()
                    if any(
                        n in window
                        for n in (
                            "do not ",
                            "don't ",
                            "never ",
                            "avoid ",
                            "must not ",
                            "without dumping",
                            "do not printenv",
                            "don't printenv",
                        )
                    ):
                        continue
                    if is_educational_context(content, m.start()) and sf.relative_path.endswith(
                        ".md"
                    ):
                        continue
                    conf = Confidence.MEDIUM
                    if "printenv" in snippet.lower() or "dump" in snippet.lower():
                        conf = Confidence.HIGH
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=sf.relative_path,
                                line=line_of(content, m.start()),
                                snippet=snippet,
                                confidence=conf,
                            )
                        )
                    )
        return findings


class CredentialFileAccessRule(RegexRule):
    meta = RuleMeta(
        id="SG-SECRET-004",
        name="Suspicious credential file access",
        description="Detects access to common credential paths (.aws, .ssh, .npmrc, cookies, etc.).",
        severity=Severity.HIGH,
        category=Category.CREDENTIALS,
        remediation="Do not read host credential files from a skill unless explicitly required and reviewed.",
        tags=("credentials", "filesystem"),
    )
    skip_educational = True
    default_confidence = Confidence.HIGH
    patterns = [
        re.compile(
            r"(?i)(~/|[/\\])(\.aws[/\\]credentials|\.ssh[/\\]id_rsa|\.ssh[/\\]id_ed25519|"
            r"\.netrc|\.npmrc|\.docker[/\\]config\.json|"
            r"AppData[/\\]Roaming[/\\]gcloud|"
            r"\.config[/\\]gcloud|/etc/shadow)"
        ),
        re.compile(
            r"(?i)(read|cat|type|open|load).{0,30}(credentials|id_rsa|\.env\b|secrets\.json)"
        ),
        re.compile(
            r"(?i)(Path\.home\(\)|expanduser).{0,80}(\.aws|\.ssh|credentials|id_rsa|id_ed25519)"
        ),
        re.compile(r"(?i)joinpath\([^\)]*['\"]\.aws['\"]"),
        re.compile(r"(?i)joinpath\([^\)]*['\"]\.ssh['\"]"),
    ]


RULES = [
    HardcodedApiKeyRule(),
    PrivateKeyRule(),
    EnvVarExposureRule(),
    CredentialFileAccessRule(),
]
