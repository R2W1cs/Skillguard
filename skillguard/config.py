"""Scanner configuration."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from pydantic import BaseModel, Field

from skillguard.models.finding import Severity


class ScanConfig(BaseModel):
    """Runtime configuration for SkillGuard scans."""

    max_file_size_bytes: int = 1_048_576  # 1 MiB
    max_files_per_skill: int = 500
    max_depth: int = 12
    follow_symlinks_inside_root: bool = False
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            "**/.git/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/.venv/**",
            "**/venv/**",
            "**/*.pyc",
        ]
    )
    fail_on: Severity | None = None
    enable_sandbox: bool = False
    sandbox_timeout_seconds: int = 30
    sandbox_strict_image: bool = False
    sandbox_image: str | None = None
    include_quality: bool = True
    rules_disabled: list[str] = Field(default_factory=list)
    show_progress: bool = True
    baseline_path: str | None = None

    @classmethod
    def from_file(cls, path: Path) -> ScanConfig:
        data = path.read_text(encoding="utf-8")
        loaded: Any = yaml.safe_load(data) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file must be a mapping: {path}")
        return cls.model_validate(loaded)

    def is_excluded(self, relative_path: str) -> bool:
        posix = relative_path.replace("\\", "/")
        while posix.startswith("./"):
            posix = posix[2:]
        path = PurePosixPath(posix)
        parts = set(path.parts)
        for pattern in self.exclude_globs:
            pat = pattern.replace("\\", "/")
            # Directory-name excludes commonly expressed as **/name/**
            if pat.startswith("**/") and pat.endswith("/**"):
                name = pat[3:-3]
                if name in parts:
                    return True
            if pat.startswith("**/") and not pat.endswith("/"):
                suffix = pat[3:]
                if path.match(suffix) or path.name == suffix.lstrip("*"):
                    return True
                if suffix.startswith("*.") and path.suffix == suffix[1:]:
                    return True
            try:
                if path.match(pat):
                    return True
            except ValueError:
                continue
            # Exact segment containment for simple names
            simple = pat.strip("*/")
            if simple and simple in parts:
                return True
        return False


DEFAULT_CONFIG = ScanConfig()
