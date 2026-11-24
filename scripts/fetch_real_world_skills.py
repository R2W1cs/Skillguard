#!/usr/bin/env python3
"""Fetch a sample of public Apache-2.0 Agent Skills for offline evaluation.

Prefers git sparse checkout; falls back to raw.githubusercontent.com for SKILL.md.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "real_world" / "anthropics-skills"

SKILL_NAMES = [
    "brand-guidelines",
    "skill-creator",
    "frontend-design",
    "mcp-builder",
    "webapp-testing",
    "doc-coauthoring",
    "internal-comms",
    "theme-factory",
]


def fetch_raw(path: str) -> bytes | None:
    url = f"https://raw.githubusercontent.com/anthropics/skills/main/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "SkillGuard-Eval/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except Exception:  # noqa: BLE001
        return None


def via_git() -> bool:
    if shutil.which("git") is None:
        return False
    tmp = ROOT.parent / "_clone_tmp"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "https://github.com/anthropics/skills.git",
                str(tmp),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        sparse_paths = [f"skills/{n}" for n in SKILL_NAMES]
        subprocess.run(
            ["git", "-C", str(tmp), "sparse-checkout", "set", *sparse_paths],
            check=True,
            capture_output=True,
            text=True,
        )
        commit = subprocess.check_output(
            ["git", "-C", str(tmp), "rev-parse", "HEAD"], text=True
        ).strip()
        ROOT.mkdir(parents=True, exist_ok=True)
        meta_skills: dict = {}
        for name in SKILL_NAMES:
            src = tmp / "skills" / name
            if not src.is_dir():
                continue
            dest = ROOT / name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
            files = [
                str(p.relative_to(dest)).replace("\\", "/") for p in dest.rglob("*") if p.is_file()
            ]
            meta_skills[name] = {"commit": commit, "files": files}
            print(name, "files", len(files))
        meta = {
            "repo": "anthropics/skills",
            "license": "Apache-2.0",
            "collected": "2026-03-24",
            "ref": "main",
            "commit": commit,
            "method": "git-sparse",
            "attribution": "https://github.com/anthropics/skills",
            "skills": meta_skills,
        }
        (ROOT / "COLLECTION.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return True
    except Exception as exc:  # noqa: BLE001
        print("git fetch failed:", exc)
        return False
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


def via_raw() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    meta_skills: dict = {}
    for name in SKILL_NAMES:
        dest = ROOT / name
        dest.mkdir(parents=True, exist_ok=True)
        content = fetch_raw(f"skills/{name}/SKILL.md")
        files: list[str] = []
        if content:
            (dest / "SKILL.md").write_bytes(content)
            files.append("SKILL.md")
        # Common optional docs
        for rel in ("README.md", "scripts/README.md", "references/README.md"):
            blob = fetch_raw(f"skills/{name}/{rel}")
            if blob:
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(blob)
                files.append(rel)
        meta_skills[name] = {"commit": "main-raw", "files": files}
        print(name, "files", len(files))
    meta = {
        "repo": "anthropics/skills",
        "license": "Apache-2.0",
        "collected": "2026-03-24",
        "ref": "main",
        "method": "raw-fallback",
        "attribution": "https://github.com/anthropics/skills",
        "skills": meta_skills,
        "limitation": "Partial file set due to API rate limits; SKILL.md prioritized.",
    }
    (ROOT / "COLLECTION.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def main() -> int:
    if via_git():
        print("wrote", ROOT / "COLLECTION.json")
        return 0
    print("falling back to raw.githubusercontent.com")
    via_raw()
    print("wrote", ROOT / "COLLECTION.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
