"""Docker sandbox runner — never mounts Docker socket or host credentials."""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillguard.models.skill import Skill
from skillguard.sandbox.policy import DEFAULT_POLICY, SandboxPolicy


@dataclass
class SandboxResult:
    performed: bool
    available: bool
    summary: str
    observations: list[str] = field(default_factory=list)
    error: str | None = None
    policy: dict[str, Any] = field(default_factory=dict)


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        import docker
    except ImportError:
        return False
    try:
        client = docker.from_env()
        client.ping()
        return True
    except Exception:  # noqa: BLE001 — availability probe
        return False


def run_sandbox_analysis(
    skill: Skill,
    policy: SandboxPolicy | None = None,
) -> SandboxResult:
    """Optionally inspect skill scripts inside an isolated container.

    Does **not** execute arbitrary skill entrypoints blindly. It runs a fixed
    observer script that lists files and performs static-ish runtime checks
    (syntax compile for Python) without network.
    """
    pol = policy or DEFAULT_POLICY
    policy_dict = pol.model_dump()

    if not docker_available():
        return SandboxResult(
            performed=False,
            available=False,
            summary="Dynamic analysis skipped: Docker unavailable or docker SDK not installed.",
            policy=policy_dict,
        )

    import docker
    from docker.errors import DockerException

    observer = r"""
import compileall, os, sys
root = '/skill'
print('SANDBOX_OK')
print('FILES', sum(len(files) for _,_,files in os.walk(root)))
# Syntax-check Python files only (no execution of module top-level beyond compile)
ok = compileall.compile_dir(root, quiet=1, force=True)
print('PY_COMPILE', 'ok' if ok else 'fail')
sys.exit(0 if ok else 2)
"""

    client = docker.from_env()
    tmp: str | None = None
    try:
        # Fail-closed image policy before any container starts
        try:
            pol.validate_image_reference(fail_closed=True)
            _verify_image_digest(client, pol)
        except ValueError as exc:
            return SandboxResult(
                performed=False,
                available=True,
                summary="Sandbox refused to start: image policy failed (fail-closed).",
                error=str(exc),
                policy=policy_dict,
            )

        tmp = tempfile.mkdtemp(prefix="skillguard-sandbox-")
        observer_path = Path(tmp) / "observer.py"
        observer_path.write_text(observer, encoding="utf-8")

        # Copy skill into a staging dir to avoid binding the live workspace writeable
        stage = Path(tmp) / "skill"
        _copy_skill(skill.root, stage)

        network_mode = "none" if (pol.network_disabled and not pol.allow_network) else "bridge"
        volumes = {
            str(stage): {"bind": pol.workdir, "mode": "ro"},
            str(Path(tmp)): {"bind": "/observer", "mode": "ro"},
        }
        # Defense-in-depth: refuse dangerous binds (incl. docker.sock)
        pol.volume_mounts_allowed(volumes)

        container = client.containers.run(
            image=pol.image,
            command=["python", "/observer/observer.py"],
            volumes=volumes,
            working_dir=pol.workdir,
            user=pol.user,
            network_mode=network_mode,
            mem_limit=pol.memory_limit,
            nano_cpus=pol.nano_cpus,
            pids_limit=pol.pids_limit,
            cap_drop=pol.cap_drop,
            security_opt=pol.security_opt,
            read_only=pol.read_only_root,
            tmpfs={"/tmp": "size=64m,mode=1777"},
            # NEVER mount docker.sock / host credentials
            privileged=False,
            detach=True,
            stdout=True,
            stderr=True,
        )
        try:
            try:
                result = container.wait(timeout=pol.timeout_seconds)
            except Exception:
                with contextlib.suppress(DockerException):
                    container.kill()
                raise
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        finally:
            with contextlib.suppress(DockerException):
                container.remove(force=True)

        observations = [line for line in logs.splitlines() if line.strip()]
        status = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        summary = f"Sandbox completed (exit={status}, network={'off' if network_mode == 'none' else 'on'})."
        return SandboxResult(
            performed=True,
            available=True,
            summary=summary,
            observations=observations[:50],
            policy=policy_dict,
        )
    except Exception as exc:  # noqa: BLE001
        return SandboxResult(
            performed=False,
            available=True,
            summary="Sandbox failed to run.",
            error=str(exc),
            policy=policy_dict,
        )
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _verify_image_digest(client: object, pol: SandboxPolicy) -> None:
    """Ensure the local/resolvable image ID matches a configured digest when required."""
    if not (pol.strict_image or pol.require_digest or pol.expected_image_digest):
        return
    image_ref = pol.image.strip()
    # Resolve image metadata; pull is not automatic here — fail closed if missing
    images = getattr(client, "images", None)
    if images is None:
        raise ValueError("Docker client cannot inspect images")
    try:
        img = images.get(image_ref)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"Unable to resolve sandbox image '{image_ref}' for digest verification: {exc}"
        ) from exc
    attrs = getattr(img, "attrs", {}) or {}
    repo_digests = attrs.get("RepoDigests") or []
    image_id = attrs.get("Id") or getattr(img, "id", "")
    expected = pol.expected_image_digest
    if expected and not expected.startswith("sha256:"):
        expected = f"sha256:{expected}"
    if pol.is_digest_pinned():
        configured = image_ref.split("@", 1)[1]
        # RepoDigests entries look like repo@sha256:...
        digest_ok = any(str(d).endswith(configured) for d in repo_digests) or configured in str(
            image_id
        )
        if not digest_ok:
            raise ValueError(
                f"Image digest verification failed for {image_ref}; "
                f"repo_digests={repo_digests}, id={image_id}"
            )
        if expected and configured != expected:
            raise ValueError(f"Image digest {configured} != expected {expected}")
    elif expected:
        digest_ok = any(str(d).endswith(expected) for d in repo_digests) or expected in str(
            image_id
        )
        if not digest_ok:
            raise ValueError(
                f"Expected digest {expected} not found for image {image_ref} "
                f"(repo_digests={repo_digests})"
            )


def _copy_skill(src: Path, dest: Path) -> None:
    """Copy skill tree without following outbound symlinks."""
    import os

    dest.mkdir(parents=True, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel = Path(dirpath).relative_to(src)
        target_dir = dest / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        # Do not follow symlinked dirs
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            s = Path(dirpath) / name
            if s.is_symlink():
                continue
            data = s.read_bytes()
            (target_dir / name).write_bytes(data)
