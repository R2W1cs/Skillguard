"""Obfuscation analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

OBF_RULES = {"SG-OBF-001", "SG-OBF-002"}

obfuscation_analyzer = RuleAnalyzer("obfuscation", OBF_RULES)
