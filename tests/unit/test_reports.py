"""JSON and SARIF report tests."""

from __future__ import annotations

import json
from pathlib import Path

from skillguard.config import ScanConfig
from skillguard.reporting.json_report import write_json_report
from skillguard.reporting.redaction import assert_no_raw_secret
from skillguard.reporting.sarif_report import build_sarif, write_sarif_report
from skillguard.scanner.engine import ScanEngine

SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"


def test_json_and_sarif_schema(malicious_secret: Path, tmp_path: Path) -> None:
    report = ScanEngine(ScanConfig(include_quality=True)).scan_path(malicious_secret)
    json_path = tmp_path / "out.json"
    sarif_path = tmp_path / "out.sarif"
    js = write_json_report(report, json_path)
    sf = write_sarif_report(report, sarif_path)
    data = json.loads(js)
    sarif = json.loads(sf)
    assert "skills" in data
    assert "scanner_version" in data
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif and sarif["runs"]
    assert "tool" in sarif["runs"][0]
    assert_no_raw_secret(js, [SECRET])
    assert_no_raw_secret(sf, [SECRET])


def test_sarif_build_structure(benign_skill: Path) -> None:
    report = ScanEngine(ScanConfig()).scan_path(benign_skill)
    sarif = build_sarif(report)
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
