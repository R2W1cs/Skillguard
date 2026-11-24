"""Third-party comparison harness tests."""

from __future__ import annotations

from pathlib import Path

from skillguard.evaluation.comparison import check_tool_available, run_comparison


def test_skillguard_available() -> None:
    avail = check_tool_available("skillguard")
    assert avail.available


def test_peers_skipped_without_install() -> None:
    # Peers are typically not installed in CI; must be SKIPPED not crash
    for tool_id in ("skillspector", "skill-scanner", "agent-scan"):
        avail = check_tool_available(tool_id)
        # Either missing (common) or present — both OK; harness must handle both
        assert avail.tool_id == tool_id


def test_run_comparison_smoke(fixtures_root: Path) -> None:
    report = run_comparison(fixtures_root, limit=5)
    assert report.tools
    sg = report.tools[0]
    assert sg.tool_id == "skillguard"
    assert sg.available
    assert sg.true_positives is not None
    text = report.format_terminal()
    assert "Caveats" in text
    assert "superiority" in report.to_json().lower() or "Caveats" in report.to_json()
