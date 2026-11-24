"""SKILL.md and skill file parsing (never executes skill code)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from skillguard.config import ScanConfig
from skillguard.models.skill import FileKind, Skill, SkillFile, SkillMetadata
from skillguard.scanner.discovery import _is_within, safe_list_files

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)

SCRIPT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".rb",
    ".pl",
    ".php",
    ".go",
    ".rs",
}
CONFIG_NAMES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    ".env",
    ".env.example",
}
TEXT_EXTENSIONS = SCRIPT_EXTENSIONS | {
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".csv",
    ".xml",
    ".html",
    ".css",
    ".ini",
    ".cfg",
    ".rst",
}


def classify_file(relative_path: str) -> FileKind:
    name = Path(relative_path).name
    lower = relative_path.replace("\\", "/").lower()
    if name.upper() == "SKILL.MD":
        return FileKind.SKILL_MD
    if name in CONFIG_NAMES or lower.endswith(".env"):
        return FileKind.CONFIG
    suffix = Path(relative_path).suffix.lower()
    if suffix in SCRIPT_EXTENSIONS or "/scripts/" in f"/{lower}/":
        return FileKind.SCRIPT
    if "/references/" in f"/{lower}/" or "/docs/" in f"/{lower}/" or suffix == ".md":
        return FileKind.REFERENCE
    if "/assets/" in f"/{lower}/":
        return FileKind.ASSET
    return FileKind.OTHER


def _decode_bytes(data: bytes) -> tuple[str, str, bool]:
    """Return (text, encoding, truncated_flag_unused)."""
    for enc in ("utf-8", "utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(enc), enc, False
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace", False


def parse_frontmatter(content: str) -> tuple[SkillMetadata, str]:
    """Parse YAML frontmatter and markdown body using safe YAML loading."""
    match = FRONTMATTER_RE.match(content)
    if not match:
        meta = SkillMetadata(parse_errors=["Missing or malformed YAML frontmatter"])
        return meta, content

    raw_fm, body = match.group(1), match.group(2)
    errors: list[str] = []
    data: object
    try:
        data = yaml.safe_load(raw_fm)
    except yaml.YAMLError as exc:
        return (
            SkillMetadata(
                parse_errors=[f"Invalid YAML frontmatter: {exc}"],
                raw_frontmatter=raw_fm,
            ),
            body,
        )

    if data is None:
        data = {}
    if not isinstance(data, dict):
        return (
            SkillMetadata(
                parse_errors=["Frontmatter must be a YAML mapping"],
                raw_frontmatter=raw_fm,
            ),
            body,
        )

    known = {
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
        "paths",
        "disable-model-invocation",
        "globs",
        "icon",
        "color",
    }
    extra = {str(k): v for k, v in data.items() if k not in known}

    metadata_field = data.get("metadata") or {}
    if metadata_field is None:
        metadata_field = {}
    if not isinstance(metadata_field, dict):
        errors.append("metadata must be a mapping of string keys to string values")
        metadata_field = {}
    else:
        # Coerce values to strings per spec
        coerced: dict[str, str] = {}
        for k, v in metadata_field.items():
            coerced[str(k)] = "" if v is None else str(v)
        metadata_field = coerced

    allowed = data.get("allowed-tools")
    if allowed is not None and not isinstance(allowed, str):
        allowed = str(allowed)

    paths = data.get("paths", data.get("globs"))
    name = data.get("name")
    description = data.get("description")

    if name is not None and not isinstance(name, str):
        errors.append("name must be a string")
        name = str(name)
    if description is not None and not isinstance(description, str):
        errors.append("description must be a string")
        description = str(description)

    return (
        SkillMetadata(
            name=name,
            description=description,
            license=str(data["license"]) if data.get("license") is not None else None,
            compatibility=(
                str(data["compatibility"]) if data.get("compatibility") is not None else None
            ),
            metadata=metadata_field,
            allowed_tools=allowed,
            paths=paths,
            extra=extra,
            parse_errors=errors,
            raw_frontmatter=raw_fm,
        ),
        body,
    )


def read_skill_file(path: Path, root: Path, config: ScanConfig) -> SkillFile | None:
    """Read a single file safely; skip / mark binary oversized content."""
    rel = str(path.relative_to(root)).replace("\\", "/")
    is_link = path.is_symlink()
    link_target: str | None = None
    if is_link:
        try:
            link_target = str(path.readlink())
            resolved = path.resolve()
            if not _is_within(root, resolved):
                return SkillFile(
                    path=path,
                    relative_path=rel,
                    kind=classify_file(rel),
                    size=0,
                    is_symlink=True,
                    symlink_target=link_target,
                    content=None,
                    binary=True,
                )
            # Read through resolved path only if inside root
            path = resolved
        except OSError:
            return SkillFile(
                path=path,
                relative_path=rel,
                kind=classify_file(rel),
                size=0,
                is_symlink=True,
                symlink_target=link_target,
                content=None,
                binary=True,
            )

    try:
        size = path.stat().st_size
    except OSError:
        return None

    kind = classify_file(rel)
    truncated = False
    if size > config.max_file_size_bytes:
        truncated = True
        try:
            data = path.read_bytes()[: config.max_file_size_bytes]
        except OSError:
            return None
    else:
        try:
            data = path.read_bytes()
        except OSError:
            return None

    # Heuristic binary detection
    if b"\x00" in data[:8192]:
        return SkillFile(
            path=path,
            relative_path=rel,
            kind=kind,
            size=size,
            truncated=truncated,
            is_symlink=is_link,
            symlink_target=link_target,
            content=None,
            binary=True,
        )

    suffix = path.suffix.lower()
    if suffix and suffix not in TEXT_EXTENSIONS and kind == FileKind.OTHER:
        # Still try decode for unknown text-like files
        pass

    text, encoding, _ = _decode_bytes(data)
    return SkillFile(
        path=path,
        relative_path=rel,
        kind=kind,
        size=size,
        encoding=encoding,
        truncated=truncated,
        is_symlink=is_link,
        symlink_target=link_target,
        content=text,
        binary=False,
    )


def load_skill(skill_root: Path, config: ScanConfig | None = None) -> Skill:
    """Load a skill directory into a Skill model without executing anything."""
    cfg = config or ScanConfig()
    root = skill_root.resolve()
    skill_md = root / "SKILL.md"
    if not skill_md.is_file() and not skill_md.is_symlink():
        raise FileNotFoundError(f"No SKILL.md in {root}")

    skill_file = read_skill_file(skill_md, root, cfg)
    content = skill_file.content if skill_file and skill_file.content is not None else ""
    metadata, body = parse_frontmatter(content)

    files: list[SkillFile] = []
    if skill_file:
        files.append(skill_file)

    for path in safe_list_files(root, cfg):
        if path.name.upper() == "SKILL.MD" and path.parent == root:
            continue
        sf = read_skill_file(path, root, cfg)
        if sf is not None:
            files.append(sf)

    name = metadata.name or root.name
    unexpected = [
        f.relative_path
        for f in files
        if f.kind == FileKind.OTHER and not f.relative_path.startswith(".")
    ]

    return Skill(
        root=root,
        name=name,
        skill_md_path=skill_md,
        metadata=metadata,
        body=body,
        files=files,
        unexpected_files=unexpected,
    )
