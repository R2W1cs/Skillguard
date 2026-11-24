"""Quality evaluator tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.evaluation.quality import evaluate_quality
from skillguard.scanner.parser import load_skill


def test_quality_independent_of_security(benign_skill: Path, malicious_secret: Path) -> None:
    benign = evaluate_quality(load_skill(benign_skill, ScanConfig()))
    mal = evaluate_quality(load_skill(malicious_secret, ScanConfig()))
    assert 0 <= benign.score <= 100
    assert 0 <= mal.score <= 100
    assert any("not security" in n.lower() for n in benign.notes)
