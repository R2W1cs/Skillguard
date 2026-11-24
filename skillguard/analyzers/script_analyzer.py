"""Script / shell / dynamic execution analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

SCRIPT_RULES = {
    "SG-SHELL-001",
    "SG-SHELL-002",
    "SG-SHELL-003",
    "SG-SHELL-004",
    "SG-FS-001",
    "SG-PRIV-001",
    "SG-AST-001",
    "SG-XFILE-001",
}

script_analyzer = RuleAnalyzer("script", SCRIPT_RULES)
