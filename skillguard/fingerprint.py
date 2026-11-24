"""Stable finding fingerprints for baselines and regression compare."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_WS = re.compile(r"\s+")


def normalize_snippet(snippet: str | None, max_len: int = 120) -> str:
    if not snippet:
        return ""
    return _WS.sub(" ", snippet.strip())[:max_len]


def stable_fingerprint(
    *,
    rule_id: str,
    file_path: str,
    title: str,
    snippet: str | None = None,
) -> str:
    """Return a stable, process-independent fingerprint.

    Line numbers are intentionally excluded so edits that only shift lines
    do not appear as brand-new findings. Evidence snippet is normalized.
    """
    payload = "|".join(
        [
            rule_id.strip(),
            file_path.replace("\\", "/").strip(),
            title.strip(),
            normalize_snippet(snippet),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def fingerprint_from_finding_dict(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    snippet = evidence.get("snippet") if isinstance(evidence, dict) else None
    existing = finding.get("fingerprint")
    if isinstance(existing, str) and len(existing) >= 8:
        return existing
    return stable_fingerprint(
        rule_id=str(finding.get("rule_id", "")),
        file_path=str(finding.get("file_path", "")),
        title=str(finding.get("title", "")),
        snippet=snippet if isinstance(snippet, str) else None,
    )


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_hash(text: str) -> str:
    return content_hash(text.encode("utf-8"))
