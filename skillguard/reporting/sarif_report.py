"""SARIF 2.1.0 report writer for GitHub Code Scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillguard import __version__
from skillguard.models.finding import Severity
from skillguard.models.report import ScanReport
from skillguard.reporting.redaction import redact_text
from skillguard.rules.registry import list_rule_metas

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFORMATIONAL: "0.0",
}


def build_sarif(report: ScanReport) -> dict[str, Any]:
    rules_meta = {r["id"]: r for r in list_rule_metas()}
    # Also include structural rules used by validator
    for sid, name in [
        ("SG-STRUCT-001", "Malformed frontmatter"),
        ("SG-STRUCT-002", "Missing name"),
        ("SG-STRUCT-003", "Name too long"),
        ("SG-STRUCT-004", "Invalid name format"),
        ("SG-STRUCT-005", "Name/directory mismatch"),
        ("SG-STRUCT-006", "Missing description"),
        ("SG-STRUCT-007", "Description too long"),
        ("SG-STRUCT-008", "Compatibility too long"),
        ("SG-STRUCT-009", "File truncated"),
        ("SG-STRUCT-010", "Symlink outside root"),
    ]:
        rules_meta.setdefault(
            sid,
            {
                "id": sid,
                "name": name,
                "severity": "medium",
                "category": "structure",
                "description": name,
            },
        )

    sarif_rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []

    for skill in report.skills:
        for finding in skill.findings:
            if finding.rule_id not in seen_rules:
                seen_rules.add(finding.rule_id)
                meta = rules_meta.get(
                    finding.rule_id,
                    {
                        "id": finding.rule_id,
                        "name": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                    },
                )
                sarif_rules.append(
                    {
                        "id": finding.rule_id,
                        "name": meta.get("name", finding.title),
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {
                            "text": redact_text(meta.get("description", finding.description))
                        },
                        "help": {"text": redact_text(finding.remediation)},
                        "defaultConfiguration": {"level": _LEVEL.get(finding.severity, "warning")},
                        "properties": {
                            "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.0"),
                            "tags": ["security", finding.category.value, *finding.tags],
                        },
                    }
                )

            physical: dict[str, Any] = {
                "artifactLocation": {
                    "uri": finding.file_path.replace("\\", "/"),
                }
            }
            if finding.line is not None:
                physical["region"] = {
                    "startLine": max(1, finding.line),
                    "startColumn": finding.column or 1,
                }
                if finding.evidence and finding.evidence.snippet:
                    physical["region"]["snippet"] = {"text": redact_text(finding.evidence.snippet)}

            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _LEVEL.get(finding.severity, "warning"),
                    "message": {"text": redact_text(f"{finding.title}: {finding.description}")},
                    "locations": [{"physicalLocation": physical}],
                    "properties": {
                        "confidence": finding.confidence.value,
                        "skill": skill.skill_name,
                        "riskScore": skill.risk.score,
                    },
                }
            )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/R2W1cs/Skillguard",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
                "properties": {
                    "scannerVersion": report.scanner_version,
                    "target": report.target,
                    "overallRisk": report.overall_risk.value,
                    "overallScore": report.overall_score,
                    "analysisLimitations": report.analysis_limitations,
                },
            }
        ],
    }


def write_sarif_report(report: ScanReport, path: Path | None = None) -> str:
    payload = json.dumps(build_sarif(report), indent=2)
    if path is not None:
        path.write_text(payload, encoding="utf-8")
    return payload
