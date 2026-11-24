"""Sandbox execution policy — secure defaults."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator

# Prefer a specific tag; production/strict mode requires digest pinning.
DEFAULT_IMAGE = "python:3.12.8-alpine"
DIGEST_RE = re.compile(r"^.+@sha256:[a-fA-F0-9]{64}$")
MUTABLE_TAG_RE = re.compile(r"^[^@]+:(latest|main|master|dev|nightly|edge)$", re.I)


class SandboxPolicy(BaseModel):
    """Explicit policy for optional dynamic analysis.

    Limitations (documented):
    - Container escapes remain a residual risk; this is not a perfect isolation boundary.
    - Network disabled by default; enabling network increases exfiltration risk.
    - Read-only root filesystem with a tmpfs scratch space.
    - No Docker socket mount, no host credential mounts.
    - Non-root user inside the container.
    - Mutable tags can move; strict mode requires digest-pinned images and verifies them.
    """

    image: str = DEFAULT_IMAGE
    network_disabled: bool = True
    read_only_root: bool = True
    user: str = "65534:65534"  # nobody
    memory_limit: str = "256m"
    nano_cpus: int = 500_000_000  # 0.5 CPU
    pids_limit: int = 64
    timeout_seconds: int = 30
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    security_opt: list[str] = Field(default_factory=lambda: ["no-new-privileges:true"])
    allow_network: bool = False  # must be explicit
    workdir: str = "/skill"
    forbid_docker_socket: bool = True
    require_non_root: bool = True
    # Production / high-assurance mode
    strict_image: bool = False
    require_digest: bool = False
    expected_image_digest: str | None = None  # sha256:... without repo prefix

    @field_validator("timeout_seconds")
    @classmethod
    def _timeout_bounds(cls, v: int) -> int:
        if v < 1 or v > 300:
            raise ValueError("timeout_seconds must be between 1 and 300")
        return v

    @model_validator(mode="after")
    def _secure_defaults(self) -> SandboxPolicy:
        if self.require_non_root:
            user = self.user.strip()
            if user in {"0", "0:0", "root", "root:root"}:
                raise ValueError("SandboxPolicy refuses root user when require_non_root=True")
        if "ALL" not in self.cap_drop:
            self.cap_drop = ["ALL", *self.cap_drop]
        if "no-new-privileges:true" not in self.security_opt:
            self.security_opt = [*self.security_opt, "no-new-privileges:true"]
        if self.strict_image:
            self.require_digest = True
        if self.require_digest or self.strict_image:
            self.validate_image_reference(fail_closed=True)
        return self

    def is_digest_pinned(self) -> bool:
        return bool(DIGEST_RE.match(self.image.strip()))

    def validate_image_reference(self, *, fail_closed: bool = True) -> None:
        image = self.image.strip()
        if MUTABLE_TAG_RE.match(image):
            msg = f"Mutable image tag rejected in strict/production mode: {image}"
            if fail_closed:
                raise ValueError(msg)
        if (self.require_digest or self.strict_image) and not self.is_digest_pinned():
            msg = (
                "strict_image/require_digest requires an immutable reference "
                f"like repo@sha256:<64-hex>, got: {image}"
            )
            if fail_closed:
                raise ValueError(msg)
        if self.expected_image_digest:
            digest = self.expected_image_digest
            if not digest.startswith("sha256:"):
                digest = f"sha256:{digest}"
            if self.is_digest_pinned() and not image.endswith(digest):
                raise ValueError(
                    f"Configured image digest mismatch: image={image}, expected={digest}"
                )

    def volume_mounts_allowed(self, binds: dict[str, dict[str, str]]) -> None:
        """Raise if mounts attempt to expose Docker socket or obvious credential paths."""
        if not self.forbid_docker_socket:
            return
        forbidden_substrings = (
            "docker.sock",
            "/.ssh",
            "/.aws",
            "/.gnupg",
            "\\Application Data\\",
        )
        for host_path, spec in binds.items():
            joined = f"{host_path}|{spec}"
            lower = joined.lower().replace("\\", "/")
            for bad in forbidden_substrings:
                if bad.lower().replace("\\", "/") in lower:
                    raise ValueError(f"Forbidden sandbox mount: {host_path}")


DEFAULT_POLICY = SandboxPolicy()
