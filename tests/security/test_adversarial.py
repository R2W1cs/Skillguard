"""Adversarial / security tests for the scanner itself."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from skillguard.config import ScanConfig
from skillguard.reporting.json_report import write_json_report
from skillguard.reporting.redaction import assert_no_raw_secret
from skillguard.reporting.sarif_report import write_sarif_report
from skillguard.reporting.terminal_report import render_terminal_report
from skillguard.scanner.discovery import find_skill_roots, safe_list_files
from skillguard.scanner.engine import ScanEngine
from skillguard.scanner.parser import load_skill


def test_path_traversal_symlink_file(tmp_path: Path) -> None:
    skill = tmp_path / "trav"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: trav\ndescription: path traversal adversarial fixture for scanner tests.\n---\n\n# T\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("SUPERSECRET_VALUE_12345", encoding="utf-8")
    link = skill / "leak.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not available")
    cfg = ScanConfig()
    loaded = load_skill(skill, cfg)
    # Content from outside should not be ingested as readable skill content
    leaked = [f for f in loaded.files if f.relative_path == "leak.txt"]
    assert leaked
    assert leaked[0].content is None or "SUPERSECRET_VALUE_12345" not in (leaked[0].content or "")


def test_large_file_truncated(tmp_path: Path) -> None:
    skill = tmp_path / "big"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: big\ndescription: large file fixture for truncation safety tests here.\n---\n\n# B\n",
        encoding="utf-8",
    )
    huge = skill / "scripts" / "huge.py"
    huge.parent.mkdir()
    huge.write_bytes(b"# " + b"A" * 2_000_000)
    cfg = ScanConfig(max_file_size_bytes=10_000)
    loaded = load_skill(skill, cfg)
    big = next(f for f in loaded.files if f.relative_path.endswith("huge.py"))
    assert big.truncated
    assert big.content is not None
    assert len(big.content.encode("utf-8", errors="replace")) <= 10_000 + 100


def test_malicious_filename(tmp_path: Path) -> None:
    skill = tmp_path / "names"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: names\ndescription: weird filename fixture for robustness tests cases.\n---\n\n# N\n",
        encoding="utf-8",
    )
    weird = skill / "scripts"
    weird.mkdir()
    (weird / "foo;rm -rf .py").write_text("print(1)\n", encoding="utf-8")
    report = ScanEngine(ScanConfig()).scan_path(skill)
    assert report.skills


def test_invalid_encoding(tmp_path: Path) -> None:
    skill = tmp_path / "enc"
    skill.mkdir()
    (skill / "SKILL.md").write_bytes(
        b"---\nname: enc\ndescription: encoding fixture for decoder robustness tests.\n---\n\n# "
        + bytes([0xFF, 0xFE, 0xFD])
        + b"\n"
    )
    # Should not crash
    loaded = load_skill(skill, ScanConfig())
    assert loaded.body is not None


def test_secret_not_in_any_report_format(malicious_secret: Path, tmp_path: Path) -> None:
    secret = "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    report = ScanEngine(ScanConfig()).scan_path(malicious_secret)
    js = write_json_report(report, tmp_path / "r.json")
    sf = write_sarif_report(report, tmp_path / "r.sarif")
    console = Console(record=True, width=120)
    render_terminal_report(report, console=console)
    term = console.export_text()
    for blob in (js, sf, term):
        assert_no_raw_secret(blob, [secret, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])


def test_max_files_cap(tmp_path: Path) -> None:
    skill = tmp_path / "many"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: many\ndescription: many files fixture for resource exhaustion bounds.\n---\n\n# M\n",
        encoding="utf-8",
    )
    for i in range(50):
        (skill / f"f{i}.txt").write_text("x", encoding="utf-8")
    files = safe_list_files(skill, ScanConfig(max_files_per_skill=10))
    assert len(files) <= 10


def test_sandbox_policy_defaults() -> None:
    from skillguard.sandbox.policy import DEFAULT_POLICY

    assert DEFAULT_POLICY.network_disabled is True
    assert DEFAULT_POLICY.read_only_root is True
    assert "ALL" in DEFAULT_POLICY.cap_drop
    assert DEFAULT_POLICY.allow_network is False


def test_discovery_does_not_follow_network(tmp_path: Path) -> None:
    # Static analysis must not fetch URLs present in skills
    skill = tmp_path / "net"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: net\ndescription: contains a URL that must not be fetched by scanner.\n---\n\n"
        "See https://example.invalid/should-not-fetch\n",
        encoding="utf-8",
    )
    roots = find_skill_roots(skill, ScanConfig())
    assert roots
    ScanEngine(ScanConfig()).scan_path(skill)
