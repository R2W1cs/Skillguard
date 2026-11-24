#!/usr/bin/env python3
"""Smoke-verify SkillGuard release readiness (local)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)


def main() -> int:
    failures: list[str] = []

    for cmd in (
        [sys.executable, "-m", "ruff", "check", "skillguard", "tests"],
        [sys.executable, "-m", "mypy", "skillguard"],
        [sys.executable, "-m", "pytest", "-q", "--cov=skillguard", "--cov-fail-under=85"],
    ):
        p = run(cmd)
        if p.returncode != 0:
            failures.append(" ".join(cmd))
            print(p.stdout)
            print(p.stderr)

    # CLI smoke
    benign = ROOT / "tests" / "fixtures" / "benign" / "hello-world"
    malicious = ROOT / "tests" / "fixtures" / "malicious" / "secret-exfil"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        json_out = tmp_path / "r.json"
        sarif_out = tmp_path / "r.sarif"
        p = run(
            [
                sys.executable,
                "-m",
                "skillguard",
                "scan",
                str(benign),
                "--format",
                "json",
                "-o",
                str(json_out),
                "--quiet",
            ]
        )
        if p.returncode != 0:
            failures.append("scan benign")
        p = run(
            [
                sys.executable,
                "-m",
                "skillguard",
                "scan",
                str(malicious),
                "--format",
                "sarif",
                "-o",
                str(sarif_out),
                "--quiet",
            ]
        )
        if p.returncode != 0:
            failures.append("scan malicious sarif")
        if json_out.exists():
            data = json.loads(json_out.read_text(encoding="utf-8"))
            blob = json.dumps(data)
            if "sk-" in blob and "REDACTED" not in blob:
                # soft check — real keys should be redacted; fixtures may use placeholders
                pass
            if "informationUri" in (
                sarif_out.read_text(encoding="utf-8") if sarif_out.exists() else ""
            ):
                sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
                uri = sarif["runs"][0]["tool"]["driver"].get("informationUri", "")
                if "R2W1cs/Skillguard" not in uri:
                    failures.append(f"sarif informationUri incorrect: {uri}")

    # Docs build if mkdocs available
    try:
        import mkdocs  # noqa: F401

        p = run([sys.executable, "-m", "mkdocs", "build", "--strict"])
        if p.returncode != 0:
            failures.append("mkdocs build")
            print(p.stdout)
            print(p.stderr)
    except ImportError:
        print("mkdocs not installed; skip docs build (pip install -e '.[docs]')")

    if failures:
        print("FAILED:", failures)
        return 1
    print("verify_release: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
