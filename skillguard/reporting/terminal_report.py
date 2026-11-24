"""Human-readable terminal report using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillguard.models.finding import Severity
from skillguard.models.report import ScanReport
from skillguard.reporting.redaction import redact_text

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFORMATIONAL: "dim",
}


def render_terminal_report(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        Panel.fit(
            f"[bold]SkillGuard[/bold] v{report.scanner_version}\n"
            f"Target: {report.target}\n"
            f"Overall risk: [bold]{report.overall_risk.value}[/bold] "
            f"(score {report.overall_score})",
            title="Scan Report",
        )
    )

    if not report.skills:
        console.print("[yellow]No skills discovered.[/yellow]")
        return

    for skill in report.skills:
        console.print()
        console.rule(f"[bold]{skill.skill_name}[/bold]")
        console.print(f"Path: {skill.skill_path}")
        console.print(
            f"Risk: {skill.risk.level.value} ({skill.risk.score}) — {skill.risk.explanation}"
        )
        if skill.quality:
            console.print(
                f"Quality (non-security): {skill.quality.score}/100 "
                f"(meta={skill.quality.metadata_completeness}, "
                f"docs={skill.quality.documentation_quality})"
            )
        if skill.exclusions_applied:
            console.print(
                "[yellow]Exclusions applied (visible):[/yellow] "
                + ", ".join(skill.exclusions_applied)
            )
        if skill.sandbox:
            console.print(f"Sandbox: {skill.sandbox}")

        if not skill.findings:
            console.print("[green]No findings.[/green]")
            continue

        table = Table(show_header=True, header_style="bold")
        table.add_column("Sev")
        table.add_column("Rule")
        table.add_column("File")
        table.add_column("Line")
        table.add_column("Title")
        for f in skill.findings:
            table.add_row(
                Text(f.severity.value, style=_SEV_STYLE.get(f.severity, "")),
                f.rule_id,
                f.file_path,
                str(f.line or "-"),
                f.title,
            )
        console.print(table)

        for f in skill.findings[:20]:
            console.print(f"  [bold]{f.rule_id}[/bold] {f.title}")
            if f.evidence:
                console.print(f"    evidence: {redact_text(f.evidence.snippet)}")
            console.print(f"    remediation: {f.remediation}")

    console.print()
    console.print("[dim]Limitations:[/dim]")
    for lim in report.analysis_limitations:
        console.print(f"  [dim]- {lim}[/dim]")
