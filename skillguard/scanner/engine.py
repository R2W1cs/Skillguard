"""Scan orchestration engine."""

from __future__ import annotations

from pathlib import Path

from skillguard import __version__
from skillguard.analyzers import default_analyzers, run_all_analyzers
from skillguard.analyzers.base import Analyzer
from skillguard.config import ScanConfig
from skillguard.evaluation.quality import evaluate_quality
from skillguard.evaluation.scoring import assess_overall_risk, assess_risk, dedupe_findings
from skillguard.models.report import ScanReport, SkillReport
from skillguard.rules.registry import all_rules
from skillguard.scanner.discovery import DiscoveryError, find_skill_roots
from skillguard.scanner.parser import load_skill
from skillguard.scanner.validator import validate_skill


class ScanEngine:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def scan_path(self, target: Path) -> ScanReport:
        target = target.resolve()
        try:
            roots = find_skill_roots(target, self.config)
        except DiscoveryError as exc:
            raise DiscoveryError(str(exc)) from exc

        skill_reports: list[SkillReport] = []
        analyzers = default_analyzers()
        checks = [a.name for a in analyzers] + ["validator", "risk-scoring"]
        if self.config.include_quality:
            checks.append("quality")
        if self.config.enable_sandbox:
            checks.append("sandbox")

        for root in roots:
            skill_reports.append(self._scan_skill(root, checks, analyzers))

        overall_level, overall_score = assess_overall_risk([s.risk for s in skill_reports])
        return ScanReport(
            scanner_version=__version__,
            target=str(target),
            skills=skill_reports,
            overall_risk=overall_level,
            overall_score=overall_score,
        )

    def _scan_skill(
        self,
        root: Path,
        checks: list[str],
        analyzers: list[Analyzer],
    ) -> SkillReport:
        skill = load_skill(root, self.config)
        findings = validate_skill(skill)
        findings.extend(run_all_analyzers(skill, analyzers, disabled=self.config.rules_disabled))
        findings = dedupe_findings(findings)
        findings = [f.with_fingerprint() for f in findings]

        # Record which rules were considered
        rule_ids = [r.meta.id for r in all_rules(self.config.rules_disabled)]

        exclusions = list(self.config.exclude_globs)
        quality = evaluate_quality(skill) if self.config.include_quality else None
        risk = assess_risk(findings)

        sandbox_info = None
        limitations = [
            "Static analysis only unless sandbox opted in.",
            "Pattern-based detectors can miss novel attacks and may false-positive.",
        ]
        if self.config.enable_sandbox:
            from skillguard.sandbox.docker_runner import run_sandbox_analysis
            from skillguard.sandbox.policy import DEFAULT_IMAGE, SandboxPolicy

            image = self.config.sandbox_image or DEFAULT_IMAGE
            policy = SandboxPolicy(
                image=image,
                timeout_seconds=self.config.sandbox_timeout_seconds,
                strict_image=self.config.sandbox_strict_image,
            )
            result = run_sandbox_analysis(skill, policy)
            sandbox_info = {
                "performed": result.performed,
                "available": result.available,
                "summary": result.summary,
                "observations": result.observations,
                "error": result.error,
                "policy": result.policy,
            }
            if not result.performed:
                limitations.append(
                    "Dynamic analysis was not performed; static results are not equivalent."
                )
        else:
            limitations.append("Sandbox dynamic analysis was not requested (--sandbox).")

        return SkillReport(
            skill_name=skill.name,
            skill_path=str(skill.root),
            findings=findings,
            risk=risk,
            quality=quality,
            files_inspected=[f.relative_path for f in skill.files],
            checks_performed=checks + rule_ids,
            exclusions_applied=exclusions,
            limitations=limitations,
            sandbox=sandbox_info,
        )
