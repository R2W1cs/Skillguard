"""Network and data exfiltration rules."""

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


class SuspiciousNetworkRule(RegexRule):
    meta = RuleMeta(
        id="SG-NET-001",
        name="Suspicious network request",
        description="Detects outbound network calls, especially to raw IPs or unusual endpoints.",
        severity=Severity.MEDIUM,
        category=Category.NETWORK,
        remediation="Document required network access; avoid hardcoding opaque endpoints or raw IPs.",
        tags=("network",),
    )
    skip_educational = True
    default_confidence = Confidence.MEDIUM
    patterns = [
        re.compile(r"(?i)\brequests\.(get|post|put|delete)\s*\("),
        re.compile(r"(?i)\bhttpx\.(get|post|request)\s*\("),
        re.compile(r"(?i)\burllib\.request\."),
        re.compile(r"(?i)\bfetch\s*\(\s*['\"]https?://"),
        re.compile(r"(?i)\baxios\.(get|post)\s*\("),
        re.compile(r"(?i)\bcurl\s+(https?://|ftp://)"),
        re.compile(r"(?i)https?://\d{1,3}(?:\.\d{1,3}){3}"),
    ]


class DataExfiltrationRule(Rule):
    meta = RuleMeta(
        id="SG-NET-002",
        name="Data exfiltration pattern",
        description="Detects patterns that collect local data and transmit it to remote endpoints.",
        severity=Severity.CRITICAL,
        category=Category.EXFILTRATION,
        remediation="Remove exfiltration logic. Skills must not send workspace secrets or files off-host silently.",
        tags=("exfiltration", "network"),
    )

    _collect = re.compile(
        r"(?i)(open\(|read_text\(|Path\(|glob\(|os\.walk\(|listdir\()",
    )
    _send = re.compile(
        r"(?i)(requests\.(post|put)|httpx\.(post|put)|urllib\.request\.urlopen|"
        r"curl\s+-.*(d|F)\s|websocket|socket\.connect)",
    )
    _combo = re.compile(
        r"(?i)(exfil|exfiltrate|webhook\.site|pastebin\.com|ngrok\.io|"
        r"send.*(secret|token|password|key|credential)|"
        r"upload.*(ssh|aws|env|credential))",
    )

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for sf in iter_text_files(skill):
            content = sf.content or ""
            for m in self._combo.finditer(content):
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
            # Same-file collect + send heuristic (scripts only)
            is_script = sf.kind.value == "script" or sf.relative_path.endswith(
                (".py", ".js", ".sh", ".ps1")
            )
            if is_script and self._collect.search(content) and self._send.search(content):
                send_m = self._send.search(content)
                assert send_m is not None
                findings.append(
                    self.finding_from_match(
                        Match(
                            file_path=sf.relative_path,
                            line=line_of(content, send_m.start()),
                            snippet=snippet_at(content, send_m.start()),
                            confidence=Confidence.MEDIUM,
                            context="File both reads local data and performs outbound send",
                        )
                    )
                )
        return findings


RULES = [
    SuspiciousNetworkRule(),
    DataExfiltrationRule(),
]
