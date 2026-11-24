"""Benchmark integration test — runs real metrics, does not fabricate them."""

from __future__ import annotations

from pathlib import Path

from skillguard.evaluation.benchmark import run_benchmark


def test_benchmark_metrics(fixtures_root: Path) -> None:
    result = run_benchmark(fixtures_root)
    assert result.true_positives > 0
    assert result.false_negatives == 0 or result.recall >= 0.7
    assert result.precision >= 0.7
    assert result.duration_seconds >= 0
    assert "Corpus is synthetic" in result.limitations[0]
