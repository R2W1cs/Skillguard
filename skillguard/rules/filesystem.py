"""Filesystem and privilege-related rules."""

from __future__ import annotations

import re

from skillguard.models.finding import Category, Confidence, Severity
from skillguard.rules.base import RegexRule, RuleMeta


class DestructiveFilesystemRule(RegexRule):
    meta = RuleMeta(
        id="SG-FS-001",
        name="Destructive filesystem operation",
        description="Detects mass-delete or overwrite patterns targeting sensitive paths.",
        severity=Severity.HIGH,
        category=Category.FILESYSTEM,
        remediation="Scope file mutations; avoid recursive deletes of sensitive directories.",
        tags=("filesystem", "destructive"),
    )
    skip_educational = True
    default_confidence = Confidence.HIGH
    patterns = [
        re.compile(r"(?i)\bshutil\.rmtree\s*\("),
        re.compile(r"(?i)\bos\.remove\s*\("),
        re.compile(r"(?i)\bPath\([^)]*\)\.unlink\s*\("),
        re.compile(r"(?i)\brm\s+-rf\s+"),
        re.compile(r"(?i)\bdel\s+/[sf]\s+"),
        re.compile(r"(?i)\bRemove-Item\s+.*-Recurse"),
    ]


class UnauthorizedFileAccessRule(RegexRule):
    meta = RuleMeta(
        id="SG-FS-002",
        name="Unauthorized or sensitive file access",
        description="Detects reads of sensitive system or user files outside the skill workspace.",
        severity=Severity.HIGH,
        category=Category.FILESYSTEM,
        remediation="Limit file access to the skill working directory; avoid absolute sensitive paths.",
        tags=("filesystem", "privacy"),
    )
    skip_educational = True
    default_confidence = Confidence.MEDIUM
    patterns = [
        re.compile(r"(?i)(/etc/passwd|/etc/shadow|/etc/sudoers)"),
        re.compile(r"(?i)([/\\]Users[/\\][^/\\]+[/\\]Documents)"),
        re.compile(r"(?i)(C:[/\\]Windows[/\\]System32)"),
        re.compile(r"(?i)(/var/run/docker\.sock)"),
        re.compile(r"(?i)(open|read|cat).{0,40}(/etc/|/root/)"),
    ]


class PrivilegeEscalationRule(RegexRule):
    meta = RuleMeta(
        id="SG-PRIV-001",
        name="Unexpected privilege escalation",
        description="Detects sudo, setuid, runas, or capability escalation patterns.",
        severity=Severity.HIGH,
        category=Category.PRIVILEGE,
        remediation=(
            "Skills should not escalate privileges. Request least privilege explicitly from users."
        ),
        tags=("privilege",),
    )
    skip_educational = True
    default_confidence = Confidence.MEDIUM
    patterns = [
        # Require a command-like sudo usage, not the bare word in prose
        re.compile(
            r"(?i)\bsudo\s+(?!apt\b|yum\b|dnf\b|apk\b|does\b|is\b|means\b|to\b|for\b|"
            r"in\b|on\b|docs?\b|commands?\b|when\b|if\b|and\b|or\b|the\b|a\b|an\b|"
            r"privileges?\b|access\b|rights?\b)"
            r"(?:-[a-zA-Z]+|[./][a-z0-9_./-]+|[a-z0-9_-]{2,}\b)"
        ),
        re.compile(r"(?i)\bchmod\s+[0-7]*[4-7][0-7]{2}\b"),  # setuid-ish
        re.compile(r"(?i)\bchown\s+root\b"),
        re.compile(r"(?i)\bStart-Process\b.*-Verb\s+RunAs"),
        re.compile(r"(?i)\bsetuid\s*\("),
        re.compile(r"(?i)\bcap_sys_admin\b"),
        re.compile(r"(?i)\b--privileged\b"),
    ]


RULES = [
    DestructiveFilesystemRule(),
    UnauthorizedFileAccessRule(),
    PrivilegeEscalationRule(),
]
