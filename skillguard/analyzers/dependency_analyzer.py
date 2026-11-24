"""Dependency / supply-chain analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

DEP_RULES = {"SG-DEP-001", "SG-DEP-002", "SG-XFILE-001"}

dependency_analyzer = RuleAnalyzer("dependency", DEP_RULES)
