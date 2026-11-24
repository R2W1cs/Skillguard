"""Rule unit tests — each major detector family."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.rules.registry import all_rules, get_rule
from skillguard.scanner.parser import load_skill


def _ids(skill_path: Path) -> set[str]:
    skill = load_skill(skill_path, ScanConfig())
    found: set[str] = set()
    for rule in all_rules():
        for f in rule.check(skill):
            found.add(f.rule_id)
    return found


def test_rules_registered() -> None:
    rules = all_rules()
    assert len(rules) >= 22
    assert get_rule("SG-SECRET-001") is not None
    assert get_rule("SG-AST-001") is not None
    assert get_rule("SG-XFILE-001") is not None


def test_secret_detection(malicious_secret: Path) -> None:
    ids = _ids(malicious_secret)
    assert "SG-SECRET-001" in ids


def test_prompt_injection(malicious_prompt: Path) -> None:
    ids = _ids(malicious_prompt)
    assert "SG-INST-001" in ids
    assert "SG-INST-003" in ids


def test_shell_danger(malicious_shell: Path) -> None:
    ids = _ids(malicious_shell)
    assert "SG-SHELL-001" in ids
    assert "SG-SHELL-003" in ids


def test_obfuscation(fixtures_root: Path) -> None:
    ids = _ids(fixtures_root / "malicious" / "obfuscated")
    assert "SG-OBF-001" in ids


def test_benign_no_critical_secrets(benign_skill: Path) -> None:
    ids = _ids(benign_skill)
    assert "SG-SECRET-001" not in ids
    assert "SG-INST-001" not in ids


def test_fp_docs_skips_educational_shell(fixtures_root: Path) -> None:
    ids = _ids(fixtures_root / "edge_cases" / "fp-docs")
    # Educational markdown should not raise dangerous shell rule
    assert "SG-SHELL-001" not in ids
