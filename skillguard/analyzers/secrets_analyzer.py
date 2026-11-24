"""Secrets analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

SECRETS_RULES = {
    "SG-SECRET-001",
    "SG-SECRET-002",
    "SG-SECRET-003",
    "SG-SECRET-004",
}

secrets_analyzer = RuleAnalyzer("secrets", SECRETS_RULES)
