"""Rule registry — single place to enumerate detectors."""

from __future__ import annotations

from skillguard.rules.ast_python import RULES as AST_RULES
from skillguard.rules.base import Rule
from skillguard.rules.cross_file import RULES as XFILE_RULES
from skillguard.rules.dependency import RULES as DEP_RULES
from skillguard.rules.filesystem import RULES as FS_RULES
from skillguard.rules.instruction import RULES as INST_RULES
from skillguard.rules.network import RULES as NET_RULES
from skillguard.rules.obfuscation import RULES as OBF_RULES
from skillguard.rules.secrets import RULES as SECRET_RULES
from skillguard.rules.shell import RULES as SHELL_RULES

_ALL: list[Rule] = [
    *SECRET_RULES,
    *SHELL_RULES,
    *FS_RULES,
    *NET_RULES,
    *OBF_RULES,
    *INST_RULES,
    *DEP_RULES,
    *AST_RULES,
    *XFILE_RULES,
]


def all_rules(disabled: list[str] | None = None) -> list[Rule]:
    disabled_set = set(disabled or [])
    return [r for r in _ALL if r.meta.id not in disabled_set]


def get_rule(rule_id: str) -> Rule | None:
    for r in _ALL:
        if r.meta.id == rule_id:
            return r
    return None


def list_rule_metas() -> list[dict[str, str]]:
    return [
        {
            "id": r.meta.id,
            "name": r.meta.name,
            "severity": r.meta.severity.value,
            "category": r.meta.category.value,
            "description": r.meta.description,
        }
        for r in _ALL
    ]
