"""AST-based Python detectors (deterministic, offline)."""

from __future__ import annotations

import ast

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import Match, Rule, RuleMeta, iter_text_files


class PythonAstSecurityRule(Rule):
    """Inspect Python ASTs for high-signal dangerous calls.

    Complements regex rules: reduces reliance on brittle string windows for
    ``subprocess(..., shell=True)`` and dotted attribute chains.
    """

    meta = RuleMeta(
        id="SG-AST-001",
        name="Python AST dangerous call",
        description=(
            "Detects dangerous Python calls via AST: os.system, eval/exec, "
            "subprocess with shell=True, and pickle.loads of untrusted data patterns."
        ),
        severity=Severity.HIGH,
        category=Category.DYNAMIC_EXEC,
        remediation=(
            "Replace eval/exec/os.system/shell=True with safe APIs and explicit argument lists."
        ),
        tags=("ast", "python"),
    )

    def check(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for sf in iter_text_files(skill):
            if not sf.relative_path.endswith(".py") or not sf.content:
                continue
            try:
                tree = ast.parse(sf.content)
            except SyntaxError:
                findings.append(
                    self.finding_from_match(
                        Match(
                            file_path=sf.relative_path,
                            line=1,
                            snippet="Python syntax error — file could not be AST-parsed",
                            confidence=Confidence.LOW,
                            severity_override=Severity.INFORMATIONAL,
                        )
                    )
                )
                continue
            for node in ast.walk(tree):
                hit = self._match_node(node)
                if hit is None:
                    continue
                kind, conf, sev = hit
                findings.append(
                    self.finding_from_match(
                        Match(
                            file_path=sf.relative_path,
                            line=getattr(node, "lineno", None),
                            snippet=kind,
                            confidence=conf,
                            severity_override=sev,
                        )
                    )
                )
        return findings

    def _match_node(self, node: ast.AST) -> tuple[str, Confidence, Severity] | None:
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"eval", "exec", "compile"}:
                return f"AST call: {name}(...)", Confidence.HIGH, Severity.HIGH
            if name in {"os.system", "os.popen", "commands.getoutput"}:
                return f"AST call: {name}(...)", Confidence.HIGH, Severity.HIGH
            if name.startswith("subprocess.") and _has_shell_true(node):
                return (
                    f"AST call: {name}(... shell=True)",
                    Confidence.HIGH,
                    Severity.HIGH,
                )
            if name in {"pickle.loads", "pickle.load", "marshal.loads"}:
                return f"AST call: {name}(...)", Confidence.MEDIUM, Severity.HIGH
            if name == "__import__":
                return "AST call: __import__(...)", Confidence.MEDIUM, Severity.MEDIUM
            if name in {"builtins.eval", "builtins.exec"}:
                return f"AST call: {name}(...)", Confidence.HIGH, Severity.HIGH
        return None


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


RULES = [PythonAstSecurityRule()]
