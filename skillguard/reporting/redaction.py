"""Secret redaction for safe evidence and report output."""

from __future__ import annotations

import re

# Patterns that look like secrets; replace with redacted placeholders.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|passwd|authorization|bearer)"
            r"(\s*[=:]\s*)([^\s'\"#,;]{8,})"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(sk-[A-Za-z0-9]{16,})\b"),
        "[REDACTED_API_KEY]",
    ),
    (
        re.compile(r"(?i)\b(ghp_[A-Za-z0-9]{20,})\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"(?i)\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        "[REDACTED_SLACK_TOKEN]",
    ),
    (
        re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"(['\"])([A-Za-z0-9+/]{40,}={0,2})\1"),
        r"\1[REDACTED_BLOB]\1",
    ),
]


def redact_text(text: str, max_len: int = 240) -> str:
    """Redact secret-like material and truncate for evidence snippets."""
    if not text:
        return text
    out = text
    for pattern, repl in _REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    if len(out) > max_len:
        out = out[: max_len - 3] + "..."
    return out


def assert_no_raw_secret(text: str, forbidden_substrings: list[str]) -> None:
    """Helper for tests: ensure raw secrets do not appear in serialized output."""
    for s in forbidden_substrings:
        if s and s in text:
            raise AssertionError(f"Secret material leaked into output: {s[:8]}...")
