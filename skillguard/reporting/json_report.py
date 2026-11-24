"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillguard.models.report import ScanReport
from skillguard.reporting.redaction import redact_text


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    data = report.model_dump(mode="json")
    # Defense-in-depth redaction pass on any string fields in findings
    for skill in data.get("skills", []):
        for finding in skill.get("findings", []):
            evidence = finding.get("evidence")
            if evidence and isinstance(evidence.get("snippet"), str):
                evidence["snippet"] = redact_text(evidence["snippet"])
            if isinstance(finding.get("description"), str):
                finding["description"] = redact_text(finding["description"])
    return data


def write_json_report(report: ScanReport, path: Path | None = None) -> str:
    payload = json.dumps(report_to_dict(report), indent=2, sort_keys=False)
    if path is not None:
        path.write_text(payload, encoding="utf-8")
    return payload
