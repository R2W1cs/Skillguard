"""SKILL.md / instruction security rules (prompt injection, concealment, secret extraction)."""

from __future__ import annotations

import re

from skillguard.models.finding import Category, Confidence, Finding, Severity
from skillguard.models.skill import Skill
from skillguard.rules.base import Match, Rule, RuleMeta, line_of, snippet_at


def _instruction_texts(skill: Skill) -> list[tuple[str, str]]:
    """Return (relative_path, text) for instruction-like documents.

    Includes description (agent-visible at discovery time) and referenced markdown.
    """
    out: list[tuple[str, str]] = []
    fm = skill.metadata.raw_frontmatter or ""
    out.append(("SKILL.md", fm + "\n" + skill.body))
    if skill.metadata.description:
        out.append(("SKILL.md#description", skill.metadata.description))
    for sf in skill.files:
        if sf.content and (
            sf.relative_path.lower().endswith(".md") or "references/" in sf.relative_path.lower()
        ):
            if sf.relative_path.upper() == "SKILL.MD":
                continue
            out.append((sf.relative_path, sf.content))
    return out


class PromptInjectionRule(Rule):
    meta = RuleMeta(
        id="SG-INST-001",
        name="Suspicious instruction override / prompt injection",
        description=(
            "Detects attempts to override system/developer instructions or ignore prior policies."
        ),
        severity=Severity.HIGH,
        category=Category.INSTRUCTION,
        remediation=(
            "Remove instruction-hierarchy manipulation. Skills should not ask agents to ignore "
            "system or developer policies."
        ),
        tags=("prompt-injection", "instruction"),
    )

    patterns = [
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,20}"
            r"\b(instructions?|rules?|policies|prompts?)\b"
        ),
        re.compile(r"(?i)\byou are now\b.{0,40}\b(unrestricted|jailbroken|DAN)\b"),
        re.compile(
            r"(?i)\boverride\b.{0,30}\b(system|developer|safety)\b.{0,20}\b(prompt|instructions?)"
        ),
        re.compile(r"(?i)\bnew system prompt\b"),
        re.compile(r"(?i)\bdo not follow\b.{0,30}\b(system|developer|user)\b"),
        re.compile(r"(?i)\bfrom now on\b.{0,60}\b(ignore|bypass)\b"),
        # Indirect / deferred injection cues
        re.compile(
            r"(?i)\b(obey|follow|comply with)\b.{0,40}\b(linked|external|fetched|referenced|"
            r"untrusted|ticket|url|html comment)\b.{0,40}\b(instructions?|directives?|commands?|rules?)\b"
        ),
        re.compile(
            r"(?i)\b(treat|use)\b.{0,40}\b(content|document|markdown|readme)\b.{0,40}"
            r"\b(higher priority|authoritative|system-level|override)\b"
        ),
        re.compile(
            r"(?i)\b(drop|set aside|remove)\b.{0,30}\b(prior|previous|earlier)\b.{0,20}"
            r"\b(constraints?|policies|instructions?)\b"
        ),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for path, text in _instruction_texts(skill):
            for pat in self.patterns:
                for m in pat.finditer(text):
                    window = text[max(0, m.start() - 48) : m.start()].lower()
                    # Educational / defensive phrasing: "never ignore previous policies"
                    if any(
                        n in window
                        for n in (
                            "never ",
                            "do not ",
                            "don't ",
                            "avoid ",
                            "must not ",
                            "warning",
                            "anti-pattern",
                            "example of",
                        )
                    ):
                        continue
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=path,
                                line=line_of(text, m.start()),
                                snippet=snippet_at(text, m.start()),
                                confidence=Confidence.HIGH,
                            )
                        )
                    )
        return findings


class SecretExtractionInstructionRule(Rule):
    meta = RuleMeta(
        id="SG-INST-002",
        name="Instruction to extract secrets via the agent",
        description="Detects instructions that ask the agent to read, reveal, or exfiltrate secrets.",
        severity=Severity.CRITICAL,
        category=Category.INSTRUCTION,
        remediation="Remove secret-harvesting instructions from SKILL.md and references.",
        tags=("secrets", "instruction"),
    )

    patterns = [
        re.compile(
            r"(?i)\b(read|extract|exfiltrate|steal|harvest|dump|print|reveal|show)\b.{0,40}"
            r"\b(api[_ -]?keys?|secrets?|tokens?|passwords?|credentials?|private keys?)\b"
        ),
        re.compile(
            r"(?i)\b(send|upload|post|exfiltrate)\b.{0,50}"
            r"\b(api[_ -]?keys?|secrets?|tokens?|passwords?|credentials?)\b"
        ),
        re.compile(r"(?i)\bsearch (the )?workspace for\b.{0,30}\b(secrets?|keys?|tokens?)\b"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for path, text in _instruction_texts(skill):
            for pat in self.patterns:
                for m in pat.finditer(text):
                    # Educational caveats: "never reveal secrets"
                    window = text[max(0, m.start() - 40) : m.start()].lower()
                    if any(n in window for n in ("never ", "do not ", "don't ", "avoid ")):
                        continue
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=path,
                                line=line_of(text, m.start()),
                                snippet=snippet_at(text, m.start()),
                                confidence=Confidence.HIGH,
                            )
                        )
                    )
        return findings


class ConcealmentInstructionRule(Rule):
    meta = RuleMeta(
        id="SG-INST-003",
        name="Instruction to conceal actions from the user",
        description="Detects instructions that tell the agent to hide actions, outputs, or intent.",
        severity=Severity.HIGH,
        category=Category.INSTRUCTION,
        remediation="Skills must not instruct agents to conceal behavior from users.",
        tags=("concealment", "instruction"),
    )

    patterns = [
        re.compile(
            r"(?i)\b(do not|don't|never)\b.{0,30}\b(tell|inform|notify|reveal to)\b.{0,20}\b(user|human)\b"
        ),
        re.compile(
            r"(?i)\bhide\b.{0,30}\b(this|these|your)\b.{0,20}\b(actions?|steps?|commands?)\b"
        ),
        re.compile(r"(?i)\bconceal\b.{0,40}\b(from the user|activity|behavior)\b"),
        re.compile(r"(?i)\bwithout (the )?user('s)? (knowledge|consent|approval)\b"),
        re.compile(r"(?i)\bsilently\b.{0,40}\b(execute|run|send|upload|exfiltrate)\b"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for path, text in _instruction_texts(skill):
            for pat in self.patterns:
                for m in pat.finditer(text):
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=path,
                                line=line_of(text, m.start()),
                                snippet=snippet_at(text, m.start()),
                                confidence=Confidence.HIGH,
                            )
                        )
                    )
        return findings


class BypassSecurityInstructionRule(Rule):
    meta = RuleMeta(
        id="SG-INST-004",
        name="Instruction to bypass security controls",
        description="Detects instructions encouraging bypass of safety, policy, or sandbox controls.",
        severity=Severity.HIGH,
        category=Category.INSTRUCTION,
        remediation="Remove guidance that encourages bypassing security or policy controls.",
        tags=("bypass", "instruction"),
    )

    patterns = [
        re.compile(
            r"(?i)\b(bypass|disable|circumvent|turn off)\b.{0,40}"
            r"\b(safety|guardrail|security|policy|sandbox|permission|approval)\b"
        ),
        re.compile(r"(?i)\bdisable\b.{0,20}\b(firewall|selinux|apparmor|antivirus)\b"),
    ]

    def check(self, skill: Skill) -> list[Finding]:
        findings = []
        for path, text in _instruction_texts(skill):
            for pat in self.patterns:
                for m in pat.finditer(text):
                    findings.append(
                        self.finding_from_match(
                            Match(
                                file_path=path,
                                line=line_of(text, m.start()),
                                snippet=snippet_at(text, m.start()),
                                confidence=Confidence.MEDIUM,
                            )
                        )
                    )
        return findings


RULES = [
    PromptInjectionRule(),
    SecretExtractionInstructionRule(),
    ConcealmentInstructionRule(),
    BypassSecurityInstructionRule(),
]
