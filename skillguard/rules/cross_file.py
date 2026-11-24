"""Cross-file correlation heuristics."""

from __future__ import annotations

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import Match, Rule, RuleMeta, iter_text_files

_DOWNLOAD_MARKERS = (
    "requests.get",
    "urllib.request",
    "urlopen",
    "httpx.get",
    "curl ",
    "wget ",
    "fetch(",
)
_EXEC_MARKERS = (
    "exec(",
    "eval(",
    "os.system",
    "subprocess",
    "shell=True",
    "| bash",
    "| sh",
    "Invoke-Expression",
)


class CrossFileDownloadExecRule(Rule):
    """Flag skills where one file downloads and another executes content."""

    meta = RuleMeta(
        id="SG-XFILE-001",
        name="Cross-file download-and-execute pattern",
        description=(
            "Detects multistage attacks where download logic and execution logic "
            "are split across files in the same skill."
        ),
        severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN,
        remediation=(
            "Keep install flows reviewable in one place; avoid download-then-exec pipelines."
        ),
        tags=("cross-file", "supply-chain"),
    )

    def check(self, skill: Skill) -> list[Finding]:
        downloaders: list[str] = []
        executors: list[str] = []
        for sf in iter_text_files(skill):
            content = (sf.content or "").lower()
            if any(m in content for m in _DOWNLOAD_MARKERS):
                downloaders.append(sf.relative_path)
            if any(m in content for m in _EXEC_MARKERS):
                executors.append(sf.relative_path)
        # Require distinct files to avoid double-counting same-file SG-SHELL-003
        down_set = set(downloaders)
        exec_set = set(executors)
        if not down_set or not exec_set:
            return []
        if down_set == exec_set and len(down_set) == 1:
            return []
        if down_set & exec_set and len(down_set | exec_set) == 1:
            return []
        # Distinct stages: all files both download and exec — need ≥2 files
        if not (down_set - exec_set) and not (exec_set - down_set) and len(down_set) < 2:
            return []
        findings: list[Finding] = []
        evidence = f"downloaders={sorted(down_set)}; executors={sorted(exec_set)}"
        findings.append(
            self.finding_from_match(
                Match(
                    file_path="SKILL.md",
                    line=1,
                    snippet=evidence[:200],
                    confidence=Confidence.MEDIUM,
                    context="Cross-file correlation",
                )
            )
        )
        return findings


RULES = [CrossFileDownloadExecRule()]
