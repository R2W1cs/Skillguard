"""Analyzers wrap rule groups for the scan engine."""

from __future__ import annotations

from skillguard.analyzers.base import Analyzer, RuleAnalyzer, run_all_analyzers


def default_analyzers() -> list[Analyzer]:
    """Default analyzer set covering all rule categories."""
    from skillguard.analyzers.dependency_analyzer import dependency_analyzer
    from skillguard.analyzers.filesystem_analyzer import filesystem_analyzer
    from skillguard.analyzers.instruction_analyzer import instruction_analyzer
    from skillguard.analyzers.network_analyzer import network_analyzer
    from skillguard.analyzers.obfuscation_analyzer import obfuscation_analyzer
    from skillguard.analyzers.script_analyzer import script_analyzer
    from skillguard.analyzers.secrets_analyzer import secrets_analyzer

    return [
        instruction_analyzer,
        script_analyzer,
        secrets_analyzer,
        network_analyzer,
        filesystem_analyzer,
        obfuscation_analyzer,
        dependency_analyzer,
    ]


__all__ = ["Analyzer", "RuleAnalyzer", "default_analyzers", "run_all_analyzers"]
