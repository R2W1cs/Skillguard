"""Finding, severity, and evidence models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    SECRETS = "secrets"
    CREDENTIALS = "credentials"
    SHELL = "shell"
    COMMAND_INJECTION = "command_injection"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    EXFILTRATION = "exfiltration"
    OBFUSCATION = "obfuscation"
    DYNAMIC_EXEC = "dynamic_execution"
    DEPENDENCY = "dependency"
    INSTRUCTION = "instruction"
    PRIVILEGE = "privilege"
    SUPPLY_CHAIN = "supply_chain"
    STRUCTURE = "structure"
    OTHER = "other"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Evidence(BaseModel):
    """Redacted evidence snippet for a finding."""

    snippet: str = Field(description="Redacted evidence text")
    line_start: int | None = None
    line_end: int | None = None
    context: str | None = None

    def model_post_init(self, __context: Any) -> None:  # noqa: ARG002
        # Defense-in-depth: never leave obvious secret-looking long tokens intact.
        from skillguard.reporting.redaction import redact_text

        object.__setattr__(self, "snippet", redact_text(self.snippet))


class Finding(BaseModel):
    """A single security finding produced by a rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: Category
    file_path: str
    line: int | None = None
    column: int | None = None
    evidence: Evidence | None = None
    remediation: str
    tags: list[str] = Field(default_factory=list)
    fingerprint: str | None = None

    def compute_fingerprint(self) -> str:
        from skillguard.fingerprint import stable_fingerprint

        snippet = self.evidence.snippet if self.evidence else None
        return stable_fingerprint(
            rule_id=self.rule_id,
            file_path=self.file_path,
            title=self.title,
            snippet=snippet,
        )

    def with_fingerprint(self) -> Finding:
        if self.fingerprint:
            return self
        return self.model_copy(update={"fingerprint": self.compute_fingerprint()})
