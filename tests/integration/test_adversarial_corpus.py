"""Adversarial corpus integrity and drift tests."""

from __future__ import annotations

import json
from pathlib import Path

from skillguard.evaluation.benchmark import load_manifest, run_manifest_benchmark


def test_manifest_exists_and_sized(fixtures_root: Path) -> None:
    manifest_path = fixtures_root / "adversarial" / "manifest.json"
    assert manifest_path.is_file()
    data = load_manifest(manifest_path)
    assert data["case_count"] >= 100
    assert len(data["cases"]) == data["case_count"]


def test_manifest_paths_exist(fixtures_root: Path) -> None:
    data = load_manifest(fixtures_root / "adversarial" / "manifest.json")
    missing = []
    for case in data["cases"]:
        if not (fixtures_root / "adversarial" / case["path"] / "SKILL.md").is_file():
            missing.append(case["id"])
    assert missing == []


def test_manifest_labels_stable_fields(fixtures_root: Path) -> None:
    data = load_manifest(fixtures_root / "adversarial" / "manifest.json")
    required = {
        "id",
        "label",
        "path",
        "expected_rules",
        "expected_severity",
        "classification",
        "explanation",
        "static_detectable",
    }
    for case in data["cases"]:
        assert required <= set(case.keys())


def test_benchmark_runs_on_adversarial(fixtures_root: Path, tmp_path: Path) -> None:
    result = run_manifest_benchmark(fixtures_root / "adversarial")
    assert result.case_count >= 100
    assert result.true_positives > 0
    assert result.duration_seconds >= 0
    # Drift guard: perfect scores are allowed on synthetic data but must be recorded
    out = tmp_path / "bench.json"
    out.write_text(result.to_json(), encoding="utf-8")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert "false_positive_rate" in loaded
    assert "by_severity" in loaded
    assert loaded["dataset"] == "adversarial-synthetic"
