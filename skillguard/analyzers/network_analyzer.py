"""Network / exfiltration analyzer."""

from __future__ import annotations

from skillguard.analyzers.base import RuleAnalyzer

NETWORK_RULES = {"SG-NET-001", "SG-NET-002"}

network_analyzer = RuleAnalyzer("network", NETWORK_RULES)
