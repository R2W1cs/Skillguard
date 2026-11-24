"""Version-to-version security regression comparison."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillguard.fingerprint import fingerprint_from_finding_dict
from skillguard.models.finding import SEVERITY_ORDER, Severity


@dataclass
class FindingRef:
    fingerprint: str
    rule_id: str
    severity: str
    title: str
    file_path: str
    skill_name: str | None = None
    snippet: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "file_path": self.file_path,
            "skill_name": self.skill_name,
            "snippet": self.snippet,
            "line": self.line,
        }


@dataclass
class CompareResult:
    old_path: str
    new_path: str
    introduced: list[FindingRef] = field(default_factory=list)
    resolved: list[FindingRef] = field(default_factory=list)
    severity_increased: list[dict[str, Any]] = field(default_factory=list)
    evidence_changed: list[dict[str, Any]] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    new_scripts: list[str] = field(default_factory=list)
    removed_files: list[str] = field(default_factory=list)
    risk_score_old: float | None = None
    risk_score_new: float | None = None
    risk_delta: float | None = None
    overall_risk_old: str | None = None
    overall_risk_new: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_path": self.old_path,
            "new_path": self.new_path,
            "introduced": [f.to_dict() for f in self.introduced],
            "resolved": [f.to_dict() for f in self.resolved],
            "severity_increased": self.severity_increased,
            "evidence_changed": self.evidence_changed,
            "new_files": self.new_files,
            "new_scripts": self.new_scripts,
            "removed_files": self.removed_files,
            "risk_score_old": self.risk_score_old,
            "risk_score_new": self.risk_score_new,
            "risk_delta": self.risk_delta,
            "overall_risk_old": self.overall_risk_old,
            "overall_risk_new": self.overall_risk_new,
            "summary": {
                "introduced_count": len(self.introduced),
                "resolved_count": len(self.resolved),
                "severity_increased_count": len(self.severity_increased),
                "evidence_changed_count": len(self.evidence_changed),
                "new_files_count": len(self.new_files),
                "new_scripts_count": len(self.new_scripts),
            },
        }

    def format_terminal(self) -> str:
        d = self.to_dict()
        lines = [
            "SkillGuard Regression Compare",
            f"  Old: {self.old_path}",
            f"  New: {self.new_path}",
            f"  Introduced: {d['summary']['introduced_count']}",
            f"  Resolved: {d['summary']['resolved_count']}",
            f"  Severity increased: {d['summary']['severity_increased_count']}",
            f"  Evidence changed: {d['summary']['evidence_changed_count']}",
            f"  New files: {d['summary']['new_files_count']} "
            f"(scripts: {d['summary']['new_scripts_count']})",
        ]
        if self.risk_delta is not None:
            lines.append(
                f"  Risk score: {self.risk_score_old} → {self.risk_score_new} "
                f"(Δ {self.risk_delta:+.1f})"
            )
            lines.append(f"  Overall risk: {self.overall_risk_old} → {self.overall_risk_new}")
        if self.introduced:
            lines.append("  New findings:")
            for f in self.introduced[:20]:
                lines.append(f"    + [{f.severity}] {f.rule_id} {f.file_path} — {f.title}")
        if self.resolved:
            lines.append("  Resolved findings:")
            for f in self.resolved[:20]:
                lines.append(f"    - [{f.severity}] {f.rule_id} {f.file_path} — {f.title}")
        if self.severity_increased:
            lines.append("  Severity increases:")
            for item in self.severity_increased[:10]:
                lines.append(
                    f"    ! {item['rule_id']} {item['file_path']}: "
                    f"{item['old_severity']} → {item['new_severity']}"
                )
        return "\n".join(lines)


def _load_report(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Report must be a JSON object: {path}")
    return data


def _iter_findings(report: dict[str, Any]) -> list[tuple[str | None, dict[str, Any]]]:
    out: list[tuple[str | None, dict[str, Any]]] = []
    for skill in report.get("skills") or []:
        name = skill.get("skill_name")
        for finding in skill.get("findings") or []:
            if isinstance(finding, dict):
                out.append((name if isinstance(name, str) else None, finding))
    # Flat findings list fallback
    for finding in report.get("findings") or []:
        if isinstance(finding, dict):
            out.append((None, finding))
    return out


def _as_ref(skill_name: str | None, finding: dict[str, Any]) -> FindingRef:
    fp = fingerprint_from_finding_dict(finding)
    evidence = finding.get("evidence") or {}
    snippet = evidence.get("snippet") if isinstance(evidence, dict) else None
    return FindingRef(
        fingerprint=fp,
        rule_id=str(finding.get("rule_id", "")),
        severity=str(finding.get("severity", "informational")),
        title=str(finding.get("title", "")),
        file_path=str(finding.get("file_path", "")),
        skill_name=skill_name,
        snippet=snippet if isinstance(snippet, str) else None,
        line=finding.get("line") if isinstance(finding.get("line"), int) else None,
    )


def _files_inspected(report: dict[str, Any]) -> set[str]:
    files: set[str] = set()
    for skill in report.get("skills") or []:
        for f in skill.get("files_inspected") or []:
            files.add(str(f).replace("\\", "/"))
    return files


def _script_files(files: set[str]) -> set[str]:
    script_ext = (".py", ".js", ".ts", ".sh", ".bash", ".ps1", ".rb", ".go")
    out: set[str] = set()
    for f in files:
        lower = f.lower()
        if lower.startswith("scripts/") or lower.endswith(script_ext):
            out.add(f)
    return out


def _overall_score(report: dict[str, Any]) -> tuple[float | None, str | None]:
    score = report.get("overall_score")
    risk = report.get("overall_risk")
    if isinstance(score, (int, float)):
        return float(score), str(risk) if risk is not None else None
    # Aggregate from skills
    skills = report.get("skills") or []
    if not skills:
        return None, str(risk) if risk is not None else None
    scores = []
    for s in skills:
        r = s.get("risk") or {}
        if isinstance(r.get("score"), (int, float)):
            scores.append(float(r["score"]))
    return (max(scores) if scores else None), (str(risk) if risk else None)


def _match_key(ref: FindingRef) -> tuple[str, str, str]:
    """Secondary key for severity/evidence drift when fingerprint differs only by snippet."""
    return (ref.rule_id, ref.file_path.replace("\\", "/"), ref.title)


def compare_reports(old_path: Path, new_path: Path) -> CompareResult:
    old = _load_report(old_path)
    new = _load_report(new_path)

    old_refs = [_as_ref(s, f) for s, f in _iter_findings(old)]
    new_refs = [_as_ref(s, f) for s, f in _iter_findings(new)]

    old_by_fp = {r.fingerprint: r for r in old_refs}
    new_by_fp = {r.fingerprint: r for r in new_refs}

    introduced = [r for fp, r in new_by_fp.items() if fp not in old_by_fp]
    resolved = [r for fp, r in old_by_fp.items() if fp not in new_by_fp]

    # Severity / evidence changes for same logical key still present under different fp
    old_by_key: dict[tuple[str, str, str], FindingRef] = {}
    for r in old_refs:
        old_by_key.setdefault(_match_key(r), r)
    new_by_key: dict[tuple[str, str, str], FindingRef] = {}
    for r in new_refs:
        new_by_key.setdefault(_match_key(r), r)

    severity_increased: list[dict[str, Any]] = []
    evidence_changed: list[dict[str, Any]] = []
    for key, new_ref in new_by_key.items():
        old_ref = old_by_key.get(key)
        if old_ref is None:
            continue
        try:
            old_sev = Severity(old_ref.severity)
            new_sev = Severity(new_ref.severity)
        except ValueError:
            continue
        if SEVERITY_ORDER[new_sev] > SEVERITY_ORDER[old_sev]:
            severity_increased.append(
                {
                    "rule_id": new_ref.rule_id,
                    "file_path": new_ref.file_path,
                    "title": new_ref.title,
                    "old_severity": old_ref.severity,
                    "new_severity": new_ref.severity,
                    "old_fingerprint": old_ref.fingerprint,
                    "new_fingerprint": new_ref.fingerprint,
                }
            )
        if (old_ref.snippet or "") != (
            new_ref.snippet or ""
        ) and old_ref.fingerprint != new_ref.fingerprint:
            evidence_changed.append(
                {
                    "rule_id": new_ref.rule_id,
                    "file_path": new_ref.file_path,
                    "title": new_ref.title,
                    "old_snippet": old_ref.snippet,
                    "new_snippet": new_ref.snippet,
                    "old_fingerprint": old_ref.fingerprint,
                    "new_fingerprint": new_ref.fingerprint,
                }
            )

    old_files = _files_inspected(old)
    new_files = _files_inspected(new)
    added_files = sorted(new_files - old_files)
    removed_files = sorted(old_files - new_files)
    new_scripts = sorted(_script_files(set(added_files)))

    score_old, risk_old = _overall_score(old)
    score_new, risk_new = _overall_score(new)
    delta = None
    if score_old is not None and score_new is not None:
        delta = round(score_new - score_old, 1)

    return CompareResult(
        old_path=str(old_path),
        new_path=str(new_path),
        introduced=sorted(introduced, key=lambda r: (r.severity, r.rule_id, r.file_path)),
        resolved=sorted(resolved, key=lambda r: (r.severity, r.rule_id, r.file_path)),
        severity_increased=severity_increased,
        evidence_changed=evidence_changed,
        new_files=added_files,
        new_scripts=new_scripts,
        removed_files=removed_files,
        risk_score_old=score_old,
        risk_score_new=score_new,
        risk_delta=delta,
        overall_risk_old=risk_old,
        overall_risk_new=risk_new,
    )


def should_fail_compare(
    result: CompareResult,
    *,
    fail_on_introduced: Severity | None = Severity.HIGH,
    fail_on_risk_increase: bool = True,
    fail_on_new_scripts: bool = False,
) -> bool:
    if fail_on_introduced is not None:
        threshold = SEVERITY_ORDER[fail_on_introduced]
        for f in result.introduced:
            try:
                if SEVERITY_ORDER[Severity(f.severity)] >= threshold:
                    return True
            except ValueError:
                continue
        for item in result.severity_increased:
            try:
                if SEVERITY_ORDER[Severity(item["new_severity"])] >= threshold:
                    return True
            except (ValueError, KeyError):
                continue
    if fail_on_risk_increase and result.risk_delta is not None and result.risk_delta > 0:
        return True
    return bool(fail_on_new_scripts and result.new_scripts)
