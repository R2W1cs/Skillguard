"""Reproducible detection benchmark against labeled corpora."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillguard.config import ScanConfig
from skillguard.models.finding import SEVERITY_ORDER, Severity
from skillguard.scanner.engine import ScanEngine

# Legacy expectations for v0.1 fixtures (kept for regression).
LEGACY_EXPECTED: dict[str, set[str]] = {
    "secret-exfil": {"SG-SECRET-001", "SG-INST-002", "SG-NET-002"},
    "prompt-inject": {"SG-INST-001", "SG-INST-003"},
    "shell-danger": {"SG-SHELL-001", "SG-SHELL-003"},
    "obfuscated": {"SG-OBF-001"},
}

BENIGN_FORBIDDEN_CRITICAL = {
    "SG-SECRET-001",
    "SG-SECRET-002",
    "SG-SHELL-001",
    "SG-SHELL-003",
    "SG-INST-001",
    "SG-INST-002",
    "SG-NET-002",
}

SEVERITY_RANK = SEVERITY_ORDER


@dataclass
class BenchmarkResult:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    by_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    duration_seconds: float = 0.0
    dataset: str = "unknown"
    dataset_version: str = "unknown"
    case_count: int = 0
    details: list[str] = field(default_factory=list)
    limitations: list[str] = field(
        default_factory=lambda: [
            "Corpus is synthetic and inert; it does not represent the full attack space.",
            "Perfect precision/recall on a labeled corpus is not proof of security.",
            "Real-world evaluation is reported separately from synthetic metrics.",
            "Cases marked static_detectable=false are excluded from FN scoring.",
        ]
    )

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return (self.true_positives / denom) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return (self.true_positives / denom) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return (self.false_positives / denom) if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return (self.false_negatives / denom) if denom else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "dataset_version": self.dataset_version,
            "case_count": self.case_count,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "duration_seconds": self.duration_seconds,
            "details": self.details,
            "limitations": self.limitations,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_terminal(self) -> str:
        d = self.to_dict()
        lines = [
            "SkillGuard Benchmark Results",
            f"  Dataset={d['dataset']} v{d['dataset_version']} cases={d['case_count']}",
            f"  TP={d['true_positives']} FP={d['false_positives']} "
            f"TN={d['true_negatives']} FN={d['false_negatives']}",
            f"  Precision={d['precision']:.3f} Recall={d['recall']:.3f} F1={d['f1']:.3f}",
            f"  FPR={d['false_positive_rate']:.3f} FNR={d['false_negative_rate']:.3f}",
            f"  Duration={d['duration_seconds']:.3f}s",
            "  By category:",
        ]
        for cat, stats in sorted(self.by_category.items()):
            lines.append(f"    - {cat}: {stats}")
        lines.append("  By severity:")
        for sev, stats in sorted(self.by_severity.items()):
            lines.append(f"    - {sev}: {stats}")
        lines.append("  Details (truncated):")
        lines.extend(f"    - {x}" for x in self.details[:40])
        if len(self.details) > 40:
            lines.append(f"    - … {len(self.details) - 40} more")
        lines.append("  Limitations:")
        lines.extend(f"    - {x}" for x in self.limitations)
        return "\n".join(lines)


def _bump(bucket: dict[str, dict[str, int]], key: str, field: str) -> None:
    bucket.setdefault(key, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    bucket[key][field] = bucket[key].get(field, 0) + 1


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    raw: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid benchmark manifest: {manifest_path}")
    data: dict[str, Any] = raw
    if "cases" not in data or "version" not in data:
        raise ValueError(f"Invalid benchmark manifest: {manifest_path}")
    return data


def run_manifest_benchmark(corpus_root: Path) -> BenchmarkResult:
    """Score the adversarial corpus using manifest labels (primary v0.2 path)."""
    manifest_path = corpus_root / "manifest.json"
    manifest = load_manifest(manifest_path)
    engine = ScanEngine(ScanConfig(include_quality=False, show_progress=False))
    result = BenchmarkResult(
        dataset="adversarial-synthetic",
        dataset_version=str(manifest.get("version", "unknown")),
        case_count=len(manifest["cases"]),
    )
    t0 = time.perf_counter()

    for case in manifest["cases"]:
        skill_path = corpus_root / case["path"]
        if not skill_path.is_dir():
            result.details.append(f"MISSING fixture {case['path']}")
            result.false_negatives += 1
            continue
        report = engine.scan_path(skill_path)
        found_rules = {f.rule_id for s in report.skills for f in s.findings}
        found_findings = [f for s in report.skills for f in s.findings]
        expected: set[str] = set(case.get("expected_rules") or [])
        classification = case.get("classification", case.get("label"))
        static_ok = bool(case.get("static_detectable", True))
        max_allowed = case.get("max_severity_allowed")

        if classification in {"benign", "fp_trap"} or case.get("label") in {
            "benign",
            "fp_trap",
        }:
            # False positive if forbidden critical family fires, or severity exceeds allowance
            bad = found_rules & BENIGN_FORBIDDEN_CRITICAL
            severity_fp = False
            if max_allowed:
                allowed_rank = SEVERITY_RANK[Severity(max_allowed)]
                severity_fp = any(SEVERITY_RANK[f.severity] > allowed_rank for f in found_findings)
            if bad or severity_fp:
                hits = bad or {f.rule_id for f in found_findings}
                result.false_positives += max(1, len(bad) if bad else 1)
                result.details.append(f"FP {case['id']}: {sorted(hits)[:5]}")
                for rid in bad:
                    _bump(result.by_category, rid.split("-")[1], "fp")
                    _bump(result.by_severity, "critical", "fp")
            else:
                result.true_negatives += 1
                result.details.append(f"TN {case['id']}")
            continue

        # malicious / mixed / detectable edge
        if not expected:
            # No labeled rules — treat as TN if nothing forbidden, else FP
            bad = found_rules & BENIGN_FORBIDDEN_CRITICAL
            if bad:
                result.false_positives += len(bad)
                result.details.append(f"FP {case['id']}: {sorted(bad)}")
            else:
                result.true_negatives += 1
                result.details.append(f"TN {case['id']}")
            continue

        if not static_ok:
            # Documented as not expected to be statically detectable — skip FN accounting
            result.details.append(f"SKIP(non-static) {case['id']}")
            continue

        for rule_id in expected:
            cat = rule_id.split("-")[1] if "-" in rule_id else "other"
            sev = case.get("expected_severity", "high")
            if rule_id in found_rules:
                result.true_positives += 1
                _bump(result.by_category, cat, "tp")
                _bump(result.by_severity, sev, "tp")
                result.details.append(f"TP {case['id']}: {rule_id}")
            else:
                result.false_negatives += 1
                _bump(result.by_category, cat, "fn")
                _bump(result.by_severity, sev, "fn")
                result.details.append(f"FN {case['id']}: missing {rule_id}")

    result.duration_seconds = round(time.perf_counter() - t0, 4)
    return result


def run_legacy_benchmark(fixtures_root: Path) -> BenchmarkResult:
    """Regression benchmark for original v0.1 fixture layout."""
    engine = ScanEngine(ScanConfig(include_quality=False, show_progress=False))
    result = BenchmarkResult(dataset="legacy-v0.1", dataset_version="0.1.0", case_count=0)
    t0 = time.perf_counter()

    malicious_root = fixtures_root / "malicious"
    if malicious_root.is_dir():
        for skill_dir in sorted(p for p in malicious_root.iterdir() if p.is_dir()):
            result.case_count += 1
            expected = LEGACY_EXPECTED.get(skill_dir.name, set())
            report = engine.scan_path(skill_dir)
            found = {f.rule_id for s in report.skills for f in s.findings}
            for rule_id in expected:
                cat = rule_id.split("-")[1] if "-" in rule_id else "other"
                if rule_id in found:
                    result.true_positives += 1
                    _bump(result.by_category, cat, "tp")
                    result.details.append(f"TP {skill_dir.name}: {rule_id}")
                else:
                    result.false_negatives += 1
                    _bump(result.by_category, cat, "fn")
                    result.details.append(f"FN {skill_dir.name}: missing {rule_id}")

    benign_root = fixtures_root / "benign"
    if benign_root.is_dir():
        for skill_dir in sorted(p for p in benign_root.iterdir() if p.is_dir()):
            result.case_count += 1
            report = engine.scan_path(skill_dir)
            found = {f.rule_id for s in report.skills for f in s.findings}
            bad = found & BENIGN_FORBIDDEN_CRITICAL
            if bad:
                result.false_positives += len(bad)
                result.details.append(f"FP {skill_dir.name}: {sorted(bad)}")
            else:
                result.true_negatives += 1
                result.details.append(f"TN {skill_dir.name}")

    fp_docs = fixtures_root / "edge_cases" / "fp-docs"
    if fp_docs.is_dir():
        result.case_count += 1
        report = engine.scan_path(fp_docs)
        shell_hits = [
            f
            for s in report.skills
            for f in s.findings
            if f.rule_id == "SG-SHELL-001" and f.file_path.endswith(".md")
        ]
        if shell_hits:
            result.false_positives += len(shell_hits)
            result.details.append(f"FP fp-docs: {len(shell_hits)}")
        else:
            result.true_negatives += 1
            result.details.append("TN fp-docs")

    mixed_root = fixtures_root / "mixed"
    if mixed_root.is_dir():
        for skill_dir in sorted(p for p in mixed_root.iterdir() if p.is_dir()):
            result.case_count += 1
            report = engine.scan_path(skill_dir)
            found = {f.rule_id for s in report.skills for f in s.findings}
            if "SG-SECRET-001" in found or "SG-SHELL-002" in found:
                result.true_positives += 1
                result.details.append(f"TP mixed {skill_dir.name}")
            else:
                result.false_negatives += 1
                result.details.append(f"FN mixed {skill_dir.name}")

    result.duration_seconds = round(time.perf_counter() - t0, 4)
    return result


def run_benchmark(fixtures_root: Path) -> BenchmarkResult:
    """Auto-select adversarial manifest when present, else legacy layout."""
    adv = fixtures_root / "adversarial" / "manifest.json"
    if adv.is_file():
        return run_manifest_benchmark(fixtures_root / "adversarial")
    if (fixtures_root / "manifest.json").is_file():
        return run_manifest_benchmark(fixtures_root)
    return run_legacy_benchmark(fixtures_root)
