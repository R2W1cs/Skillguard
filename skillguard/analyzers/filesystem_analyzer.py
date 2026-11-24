"""Filesystem analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

FS_RULES = {"SG-FS-001", "SG-FS-002", "SG-PRIV-001"}

filesystem_analyzer = RuleAnalyzer("filesystem", FS_RULES)
