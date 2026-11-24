"""Sandbox policy security tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from skillguard.sandbox.policy import DEFAULT_POLICY, SandboxPolicy


def test_default_policy_hardened() -> None:
    p = DEFAULT_POLICY
    assert p.network_disabled is True
    assert p.read_only_root is True
    assert p.allow_network is False
    assert p.forbid_docker_socket is True
    assert "ALL" in p.cap_drop
    assert "no-new-privileges:true" in p.security_opt
    assert p.user not in {"0", "root", "0:0"}


def test_refuses_root_user() -> None:
    with pytest.raises(ValidationError):
        SandboxPolicy(user="0:0")


def test_timeout_bounds() -> None:
    with pytest.raises(ValidationError):
        SandboxPolicy(timeout_seconds=0)
    with pytest.raises(ValidationError):
        SandboxPolicy(timeout_seconds=999)


def test_forbidden_docker_sock_mount() -> None:
    p = SandboxPolicy()
    with pytest.raises(ValueError, match="Forbidden"):
        p.volume_mounts_allowed({"/var/run/docker.sock": {"bind": "/sock", "mode": "rw"}})


def test_allows_skill_bind() -> None:
    p = SandboxPolicy()
    p.volume_mounts_allowed({"/tmp/skill": {"bind": "/skill", "mode": "ro"}})
