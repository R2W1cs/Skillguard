"""Instruction / prompt-injection analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

INSTRUCTION_RULES = {
    "SG-INST-001",
    "SG-INST-002",
    "SG-INST-003",
    "SG-INST-004",
    "SG-OBF-002",
}

instruction_analyzer = RuleAnalyzer("instruction", INSTRUCTION_RULES)
