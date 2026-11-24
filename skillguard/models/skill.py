"""Skill representation models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class FileKind(StrEnum):
    SKILL_MD = "skill_md"
    SCRIPT = "script"
    REFERENCE = "reference"
    ASSET = "asset"
    CONFIG = "config"
    OTHER = "other"


class SkillMetadata(BaseModel):
    """Parsed SKILL.md frontmatter aligned with Agent Skills spec."""

    name: str | None = None
    description: str | None = None
    license: str | None = None
    compatibility: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    allowed_tools: str | None = None
    paths: list[str] | str | None = None
    extra: dict[str, object] = Field(default_factory=dict)
    parse_errors: list[str] = Field(default_factory=list)
    raw_frontmatter: str | None = None


class SkillFile(BaseModel):
    """A file belonging to a skill (never executed by the scanner)."""

    path: Path
    relative_path: str
    kind: FileKind
    size: int
    encoding: str = "utf-8"
    truncated: bool = False
    is_symlink: bool = False
    symlink_target: str | None = None
    content: str | None = None
    binary: bool = False


class Skill(BaseModel):
    """A discovered and parsed Agent Skill."""

    root: Path
    name: str
    skill_md_path: Path
    metadata: SkillMetadata
    body: str = ""
    files: list[SkillFile] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    unexpected_files: list[str] = Field(default_factory=list)

    @property
    def scripts(self) -> list[SkillFile]:
        return [f for f in self.files if f.kind == FileKind.SCRIPT]

    @property
    def references(self) -> list[SkillFile]:
        return [f for f in self.files if f.kind == FileKind.REFERENCE]
