"""Stable fingerprint tests."""

from __future__ import annotations

from skillguard.fingerprint import fingerprint_from_finding_dict, stable_fingerprint
from skillguard.models.finding import Category, Confidence, Evidence, Finding, Severity


def test_fingerprint_ignores_line_numbers() -> None:
    snip = "os.system(user_input)"
    a = stable_fingerprint(
        rule_id="SG-SHELL-001",
        file_path="scripts/a.py",
        title="Dangerous shell",
        snippet=snip,
    )
    b = Finding(
        rule_id="SG-SHELL-001",
        title="Dangerous shell",
        description="d",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SHELL,
        file_path="scripts/a.py",
        line=99,
        evidence=Evidence(snippet=snip, line_start=99),
        remediation="r",
    ).compute_fingerprint()
    assert a == b


def test_path_normalization() -> None:
    a = stable_fingerprint(rule_id="R", file_path=r"scripts\x.py", title="t", snippet="s")
    b = stable_fingerprint(rule_id="R", file_path="scripts/x.py", title="t", snippet="s")
    assert a == b


def test_snippet_whitespace_normalization() -> None:
    a = stable_fingerprint(rule_id="R", file_path="f", title="t", snippet="a   b\n c")
    b = stable_fingerprint(rule_id="R", file_path="f", title="t", snippet="a b c")
    assert a == b


def test_fingerprint_from_dict_uses_existing() -> None:
    d = {"fingerprint": "abc123456789", "rule_id": "R", "file_path": "f", "title": "t"}
    assert fingerprint_from_finding_dict(d) == "abc123456789"
