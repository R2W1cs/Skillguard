"""Spec validator tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.scanner.parser import load_skill
from skillguard.scanner.validator import validate_skill


def test_malformed_frontmatter_findings(fixtures_root: Path) -> None:
    skill = load_skill(fixtures_root / "edge_cases" / "malformed-frontmatter", ScanConfig())
    findings = validate_skill(skill)
    ids = {f.rule_id for f in findings}
    assert findings
    # name should be invalid format or type issues
    assert ids & {
        "SG-STRUCT-001",
        "SG-STRUCT-002",
        "SG-STRUCT-004",
        "SG-STRUCT-006",
    }
