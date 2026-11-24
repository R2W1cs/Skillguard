"""Reproducible audit manifests for trust verification."""

from __future__ import annotations

import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from skillguard import __version__
from skillguard.fingerprint import content_hash, text_hash
from skillguard.models.report import ScanReport
from skillguard.rules.registry import list_rule_metas

RULESET_VERSION = "0.3.0"


class FileHash(BaseModel):
    path: str
    sha256: str
    size: int


class AuditManifest(BaseModel):
    """Versioned, deterministic audit artifact.

    A signature over this manifest (via cosign/sigstore/gpg — see docs) proves
    integrity and signer identity of the *report*, not the safety of the skill.
    """

    schema_version: int = 1
    skillguard_version: str = __version__
    ruleset_version: str = RULESET_VERSION
    skill_identifier: str
    skill_version: str | None = None
    source_commit: str | None = None
    scanned_path: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    config_hash: str
    ruleset_hash: str
    environment: dict[str, str] = Field(default_factory=dict)
    file_hashes: list[FileHash] = Field(default_factory=list)
    files_hash: str = ""  # hash over canonical file hash list
    findings_hash: str = ""
    overall_risk: str = ""
    overall_score: float = 0.0
    finding_count: int = 0
    suppressed_count: int = 0
    limitations: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    suppression: dict[str, Any] | None = None

    def to_canonical_json(self) -> str:
        """Deterministic JSON (sorted keys, stable separators, UTC ISO)."""
        data = json.loads(self.model_dump_json())
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"

    def content_digest(self) -> str:
        return text_hash(self.to_canonical_json())


def hash_ruleset() -> str:
    metas = list_rule_metas()
    payload = json.dumps(metas, sort_keys=True, separators=(",", ":"))
    return text_hash(payload + f"|{RULESET_VERSION}")


def hash_config(config_dict: dict[str, Any]) -> str:
    # Exclude ephemeral/runtime-only keys
    cleaned = {k: v for k, v in sorted(config_dict.items()) if k not in {"show_progress"}}
    return text_hash(json.dumps(cleaned, sort_keys=True, default=str))


def collect_file_hashes(skill_root: Path, relative_paths: list[str]) -> list[FileHash]:
    hashes: list[FileHash] = []
    root = skill_root.resolve()
    for rel in sorted(set(p.replace("\\", "/") for p in relative_paths)):
        path = root / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        hashes.append(FileHash(path=rel, sha256=content_hash(data), size=len(data)))
    return hashes


def environment_info() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "executable": sys.executable,
    }


def build_audit_manifest(
    report: ScanReport,
    *,
    config_dict: dict[str, Any],
    skill_version: str | None = None,
    source_commit: str | None = None,
    suppression: dict[str, Any] | None = None,
) -> list[AuditManifest]:
    """Build one manifest per skill in the report."""
    manifests: list[AuditManifest] = []
    ruleset_h = hash_ruleset()
    config_h = hash_config(config_dict)
    env = environment_info()

    for skill in report.skills:
        root = Path(skill.skill_path)
        file_hashes = collect_file_hashes(root, skill.files_inspected)
        files_blob = json.dumps(
            [h.model_dump() for h in file_hashes],
            sort_keys=True,
            separators=(",", ":"),
        )
        findings = [json.loads(f.with_fingerprint().model_dump_json()) for f in skill.findings]
        findings_blob = json.dumps(findings, sort_keys=True, separators=(",", ":"))
        suppressed_count = 0
        if suppression:
            suppressed_count = len(
                [
                    s
                    for s in suppression.get("suppressed", [])
                    if s.get("skill_name") == skill.skill_name
                ]
            )
        manifests.append(
            AuditManifest(
                skill_identifier=skill.skill_name,
                skill_version=skill_version,
                source_commit=source_commit,
                scanned_path=str(root),
                config_hash=config_h,
                ruleset_hash=ruleset_h,
                environment=env,
                file_hashes=file_hashes,
                files_hash=text_hash(files_blob),
                findings_hash=text_hash(findings_blob),
                overall_risk=skill.risk.level.value,
                overall_score=skill.risk.score,
                finding_count=len(findings),
                suppressed_count=suppressed_count,
                limitations=list(skill.limitations) + list(report.analysis_limitations),
                findings=findings,
                suppression=suppression,
            )
        )
    return manifests


def write_audit_manifest(manifest: AuditManifest, path: Path) -> str:
    text = manifest.to_canonical_json()
    path.write_text(text, encoding="utf-8")
    return text


def verify_manifest_digest(path: Path, expected: str | None = None) -> str:
    text = path.read_text(encoding="utf-8")
    digest = text_hash(text if text.endswith("\n") else text + "\n")
    # Re-canonicalize if needed
    data = json.loads(text)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    digest = text_hash(canonical)
    if expected and digest != expected:
        raise ValueError(f"Manifest digest mismatch: got {digest}, expected {expected}")
    return digest
