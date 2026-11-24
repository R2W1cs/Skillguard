"""Obfuscation and encoded payload rules."""

from __future__ import annotations

import base64
import binascii
import re

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import Match, Rule, RuleMeta, iter_text_files, line_of, snippet_at

SUSPICIOUS_DECODED = re.compile(
    r"(?i)(eval|exec|os\.system|subprocess|/bin/sh|powershell|Invoke-Expression|"
    r"curl\s+|wget\s+|socket\.connect|exfil)"
)


class ObfuscatedCodeRule(Rule):
    meta = RuleMeta(
        id="SG-OBF-001",
        name="Obfuscated or encoded payload",
        description="Detects base64/hex encoded blobs that decode to suspicious commands.",
        severity=Severity.HIGH,
        category=Category.OBFUSCATION,
        remediation="Avoid shipping encoded payloads. Keep scripts readable and reviewable.",
        tags=("obfuscation",),
    )

    _b64 = re.compile(r"(?i)(?:base64|b64decode|atob)\s*\(\s*['\"]([A-Za-z0-9+/=]{24,})['\"]")
    _b64_assign = re.compile(r"(?i)(?:payload|data|code|cmd)\s*=\s*['\"]([A-Za-z0-9+/=]{24,})['\"]")
    _hex = re.compile(r"(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}")
    _chr_join = re.compile(r"(?i)(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){6,}")

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for pat in (self._b64, self._b64_assign):
                for m in pat.finditer(content):
                    blob = m.group(1)
                    conf = Confidence.MEDIUM
                    try:
                        decoded = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
                        if SUSPICIOUS_DECODED.search(decoded):
                            conf = Confidence.HIGH
                        else:
                            # Long opaque blobs still informational/medium
                            conf = Confidence.LOW
                    except (binascii.Error, ValueError):
                        conf = Confidence.LOW
                    if conf == Confidence.LOW and len(blob) < 80:
                        continue
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
            for m in self._hex.finditer(content):
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
            for m in self._chr_join.finditer(content):
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


class HiddenInstructionRule(Rule):
    meta = RuleMeta(
        id="SG-OBF-002",
        name="Hidden or zero-width instruction content",
        description="Detects zero-width characters or HTML comment tricks that may hide instructions.",
        severity=Severity.MEDIUM,
        category=Category.OBFUSCATION,
        remediation="Remove zero-width characters and hidden HTML comments from skill instructions.",
        tags=("obfuscation", "steganography"),
    )

    _zw = re.compile("[\u200b\u200c\u200d\ufeff\u2060\u202a-\u202e]")

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            if self._zw.search(content):
                m = self._zw.search(content)
                assert m is not None
                findings.append(
                    self.finding_from_match(
                        Match(
                            file_path=sf.relative_path,
                            line=line_of(content, m.start()),
                            snippet="Zero-width or bidirectional control characters present",
                            confidence=Confidence.HIGH,
                        )
                    )
                )
            # Suspicious HTML comments with instruction verbs
            for m in re.finditer(r"(?is)<!--(.{0,200})-->", content):
                inner = m.group(1).lower()
                if any(
                    w in inner
                    for w in ("ignore", "secret", "password", "system prompt", "do not tell")
                ):
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


RULES = [
    ObfuscatedCodeRule(),
    HiddenInstructionRule(),
]
