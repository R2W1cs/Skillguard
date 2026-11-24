"""Skill discovery with path traversal and symlink protections."""

from __future__ import annotations

import os
from pathlib import Path

from skillguard.config import ScanConfig


class DiscoveryError(Exception):
    """Raised when discovery cannot proceed safely."""


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def find_skill_roots(target: Path, config: ScanConfig | None = None) -> list[Path]:
    """Discover directories that contain a SKILL.md file.

    If ``target`` itself is a skill root, return it alone.
    Otherwise search recursively up to ``config.max_depth``.
    """
    cfg = config or ScanConfig()
    target = target.resolve()

    if not target.exists():
        raise DiscoveryError(f"Path does not exist: {target}")

    if target.is_file():
        if target.name.upper() == "SKILL.MD":
            return [target.parent]
        raise DiscoveryError(f"Expected a skill directory or SKILL.md, got file: {target}")

    skill_md = target / "SKILL.md"
    if skill_md.is_file():
        return [target]

    roots: list[Path] = []
    base_depth = len(target.parts)

    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        current = Path(dirpath)
        depth = len(current.parts) - base_depth
        if depth > cfg.max_depth:
            dirnames[:] = []
            continue

        # Prune excluded / dangerous dirs
        pruned: list[str] = []
        for d in list(dirnames):
            child = current / d
            rel = str(child.relative_to(target)).replace("\\", "/")
            if cfg.is_excluded(rel) or cfg.is_excluded(f"{rel}/"):
                continue
            if child.is_symlink():
                # Never descend into symlinked directories during discovery
                continue
            if not _is_within(target, child):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        if "SKILL.md" in filenames:
            candidate = current / "SKILL.md"
            if candidate.is_symlink():
                # Allow SKILL.md only if it resolves inside the skill dir / target
                try:
                    resolved = candidate.resolve()
                    if not _is_within(target, resolved):
                        continue
                except OSError:
                    continue
            roots.append(current)

    roots.sort(key=lambda p: str(p).lower())
    return roots


def safe_list_files(skill_root: Path, config: ScanConfig) -> list[Path]:
    """List files under a skill root without escaping via symlinks."""
    root = skill_root.resolve()
    files: list[Path] = []
    base_depth = len(root.parts)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.parts) - base_depth
        if depth > config.max_depth:
            dirnames[:] = []
            continue

        kept_dirs: list[str] = []
        for d in dirnames:
            child = current / d
            rel = str(child.relative_to(root)).replace("\\", "/")
            if config.is_excluded(rel):
                continue
            if child.is_symlink():
                continue
            if not _is_within(root, child):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for name in filenames:
            path = current / name
            rel = str(path.relative_to(root)).replace("\\", "/")
            if config.is_excluded(rel):
                continue
            files.append(path)
            if len(files) >= config.max_files_per_skill:
                return files

    return files
