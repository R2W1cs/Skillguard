"""Third-party scanner comparison framework (reproducible evaluation harness).

This module does **not** claim SkillGuard superiority. It records comparable
metrics when peer scanners are installed and can consume the same fixtures.
Peers that require proprietary APIs or incompatible input formats are marked
SKIPPED with reasons.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from skillguard import __version__
from skillguard.config import ScanConfig
from skillguard.scanner.engine import ScanEngine

# Public peer projects (docs-verified; no proprietary code copied)
PEER_TOOLS: dict[str, dict[str, Any]] = {
    "skillguard": {
        "name": "SkillGuard",
        "repo": "local",
        "install": "pip install skillguard",
        "offline": True,
        "notes": "Deterministic static analysis; optional digest-pinned sandbox.",
    },
    "skillspector": {
        "name": "NVIDIA SkillSpector",
        "repo": "https://github.com/NVIDIA/SkillSpector",
        "install": "See upstream README (LangGraph pipeline; optional LLM).",
        "offline": "partial",
        "cli_guess": ["skillspector", "--help"],
        "notes": "LLM stage optional; baselines documented; not evaluated unless installed.",
    },
    "skill-scanner": {
        "name": "Cisco AI Defense Skill Scanner",
        "repo": "https://github.com/cisco-ai-defense/skill-scanner",
        "install": "See upstream README (YARA/policy; optional cloud).",
        "offline": "partial",
        "cli_guess": ["skill-scanner", "--help"],
        "notes": "Optional VirusTotal/cloud/LLM reduce offline purity.",
    },
    "agent-scan": {
        "name": "Snyk Agent Scan",
        "repo": "https://github.com/snyk/agent-scan",
        "install": "See upstream README (API-oriented).",
        "offline": False,
        "cli_guess": ["agent-scan", "--help"],
        "notes": "Likely API-dependent; offline comparison often not possible.",
    },
}


@dataclass
class ToolAvailability:
    tool_id: str
    available: bool
    version_or_path: str | None = None
    reason: str | None = None


@dataclass
class FixtureResult:
    fixture_id: str
    expected_malicious: bool | None
    detected: bool | None
    finding_count: int | None = None
    runtime_ms: float | None = None
    error: str | None = None
    notes: str | None = None


@dataclass
class ToolComparison:
    tool_id: str
    name: str
    available: bool
    offline_capable: bool | str
    installation_complexity: str
    runtime_total_ms: float | None = None
    true_positives: int | None = None
    false_positives: int | None = None
    false_negatives: int | None = None
    true_negatives: int | None = None
    fixtures: list[FixtureResult] = field(default_factory=list)
    output_quality_notes: str = ""
    limitations: list[str] = field(default_factory=list)
    skipped_reason: str | None = None


@dataclass
class ComparisonReport:
    skillguard_version: str
    generated_at: str
    fixture_root: str
    tools: list[ToolComparison] = field(default_factory=list)
    caveats: list[str] = field(
        default_factory=lambda: [
            "Do not claim superiority without matching input formats and equal capability scope.",
            "Peers not installed locally are recorded as SKIPPED, not as failures.",
            "Detection differences may reflect different threat models, not quality.",
            "LLM/cloud scanners are non-deterministic; offline scores are not comparable 1:1.",
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "skillguard_version": self.skillguard_version,
            "generated_at": self.generated_at,
            "fixture_root": self.fixture_root,
            "tools": [asdict(t) for t in self.tools],
            "caveats": self.caveats,
            "peer_catalog": PEER_TOOLS,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    def format_terminal(self) -> str:
        lines = [
            "SkillGuard Third-Party Comparison",
            f"  SkillGuard: {self.skillguard_version}",
            f"  Fixtures: {self.fixture_root}",
            "",
        ]
        for t in self.tools:
            status = "AVAILABLE" if t.available else "SKIPPED"
            lines.append(f"[{status}] {t.name} ({t.tool_id})")
            if t.skipped_reason:
                lines.append(f"  reason: {t.skipped_reason}")
            if t.true_positives is not None:
                lines.append(
                    f"  TP={t.true_positives} FP={t.false_positives} "
                    f"FN={t.false_negatives} TN={t.true_negatives}"
                )
            if t.runtime_total_ms is not None:
                lines.append(f"  runtime_ms={t.runtime_total_ms:.1f}")
            lines.append(f"  offline={t.offline_capable} install={t.installation_complexity}")
            lines.append("")
        lines.append("Caveats:")
        for c in self.caveats:
            lines.append(f"  - {c}")
        return "\n".join(lines)


def check_tool_available(tool_id: str) -> ToolAvailability:
    meta = PEER_TOOLS.get(tool_id)
    if meta is None:
        return ToolAvailability(tool_id, False, reason="unknown tool")
    if tool_id == "skillguard":
        return ToolAvailability(tool_id, True, version_or_path=__version__)
    for cmd in meta.get("cli_guess") or []:
        # Only first token is the binary
        binary = cmd if isinstance(cmd, str) else cmd[0]
        path = shutil.which(binary)
        if path:
            return ToolAvailability(tool_id, True, version_or_path=path)
    return ToolAvailability(
        tool_id,
        False,
        reason=f"CLI not found on PATH; install per {meta.get('repo')}",
    )


def _load_adversarial_labels(fixture_root: Path) -> list[tuple[Path, bool, str]]:
    """Return (skill_dir, expected_malicious, fixture_id) from adversarial layout."""
    adv = fixture_root / "adversarial"
    if not adv.is_dir():
        adv = fixture_root
    out: list[tuple[Path, bool, str]] = []
    for skill_md in sorted(adv.rglob("SKILL.md")):
        skill_dir = skill_md.parent
        rel = skill_dir.relative_to(adv).as_posix()
        # Heuristic from directory naming conventions used in SkillGuard corpus
        parts = rel.lower()
        if "/malicious/" in f"/{parts}/" or parts.startswith("malicious/"):
            expected = True
        elif (
            "/fp_trap/" in f"/{parts}/"
            or parts.startswith("fp_trap/")
            or "/benign/" in f"/{parts}/"
            or parts.startswith("benign/")
        ):
            expected = False
        elif "/mixed/" in f"/{parts}/":
            expected = True  # mixed corpus cases are labeled malicious-capable
        else:
            expected = "malicious" in parts
        out.append((skill_dir, expected, rel))
    return out


def _run_skillguard_fixture(skill_dir: Path) -> FixtureResult:
    engine = ScanEngine(ScanConfig(show_progress=False, include_quality=False))
    t0 = time.perf_counter()
    try:
        report = engine.scan_path(skill_dir)
        ms = (time.perf_counter() - t0) * 1000
        findings = report.all_findings
        # Detected = any finding at medium+ (security signal)
        from skillguard.models.finding import SEVERITY_ORDER, Severity

        detected = any(
            SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.MEDIUM] for f in findings
        )
        return FixtureResult(
            fixture_id=skill_dir.name,
            expected_malicious=None,
            detected=detected,
            finding_count=len(findings),
            runtime_ms=ms,
        )
    except Exception as exc:  # noqa: BLE001
        return FixtureResult(
            fixture_id=skill_dir.name,
            expected_malicious=None,
            detected=None,
            error=str(exc),
            runtime_ms=(time.perf_counter() - t0) * 1000,
        )


def evaluate_skillguard(fixture_root: Path, limit: int | None = None) -> ToolComparison:
    labeled = _load_adversarial_labels(fixture_root)
    if limit is not None:
        labeled = labeled[:limit]
    tp = fp = fn = tn = 0
    fixtures: list[FixtureResult] = []
    total_ms = 0.0
    for skill_dir, expected, fid in labeled:
        res = _run_skillguard_fixture(skill_dir)
        res.fixture_id = fid
        res.expected_malicious = expected
        fixtures.append(res)
        if res.runtime_ms:
            total_ms += res.runtime_ms
        if res.detected is None:
            continue
        if expected and res.detected:
            tp += 1
        elif expected and not res.detected:
            fn += 1
        elif not expected and res.detected:
            fp += 1
        else:
            tn += 1
    return ToolComparison(
        tool_id="skillguard",
        name="SkillGuard",
        available=True,
        offline_capable=True,
        installation_complexity="low (pip install)",
        runtime_total_ms=round(total_ms, 1),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        fixtures=fixtures,
        output_quality_notes="JSON/SARIF/terminal with redaction; fingerprints; audit manifests.",
        limitations=["Pattern/AST static analysis; optional sandbox not required for scores."],
    )


def evaluate_peer_placeholder(tool_id: str) -> ToolComparison:
    meta = PEER_TOOLS[tool_id]
    avail = check_tool_available(tool_id)
    offline = meta.get("offline", False)
    complexity = "medium–high (see upstream)" if tool_id != "skillguard" else "low"
    if not avail.available:
        return ToolComparison(
            tool_id=tool_id,
            name=meta["name"],
            available=False,
            offline_capable=offline,
            installation_complexity=complexity,
            skipped_reason=avail.reason,
            limitations=[meta.get("notes", "")],
            output_quality_notes="Not measured — tool not installed in this environment.",
        )
    # Tool is on PATH but we do not invent adapters without verified CLI contracts
    return ToolComparison(
        tool_id=tool_id,
        name=meta["name"],
        available=True,
        offline_capable=offline,
        installation_complexity=complexity,
        skipped_reason=(
            "Installed, but SkillGuard does not ship an unverified adapter for this CLI. "
            "Record availability only; run peer manually on the same fixtures for detection diffs."
        ),
        limitations=[meta.get("notes", "")],
        output_quality_notes="Availability verified; detection metrics not auto-claimed.",
    )


def run_comparison(
    fixture_root: Path,
    *,
    limit: int | None = None,
    include_peers: bool = True,
) -> ComparisonReport:
    from datetime import UTC, datetime

    tools: list[ToolComparison] = [evaluate_skillguard(fixture_root, limit=limit)]
    if include_peers:
        for tool_id in ("skillspector", "skill-scanner", "agent-scan"):
            tools.append(evaluate_peer_placeholder(tool_id))
    return ComparisonReport(
        skillguard_version=__version__,
        generated_at=datetime.now(UTC).isoformat(),
        fixture_root=str(fixture_root.resolve()),
        tools=tools,
    )


def try_run_external(cmd: list[str], timeout: int = 120) -> tuple[int, str, str, float]:
    """Helper for future verified adapters — runs a command and times it."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        ms = (time.perf_counter() - t0) * 1000
        return proc.returncode, proc.stdout, proc.stderr, ms
    except FileNotFoundError:
        return 127, "", "not found", (time.perf_counter() - t0) * 1000
    except subprocess.TimeoutExpired:
        return 124, "", "timeout", (time.perf_counter() - t0) * 1000
