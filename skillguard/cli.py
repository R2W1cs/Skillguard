"""SkillGuard command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from skillguard import __version__
from skillguard.audit import build_audit_manifest, write_audit_manifest
from skillguard.baseline import (
    Baseline,
    accept_finding,
    annotate_report,
    load_baseline,
    max_active_severity,
    save_baseline,
)
from skillguard.compare import compare_reports, should_fail_compare
from skillguard.config import ScanConfig
from skillguard.models.finding import SEVERITY_ORDER, Severity
from skillguard.models.report import RiskLevel, ScanReport
from skillguard.reporting.json_report import write_json_report
from skillguard.reporting.sarif_report import write_sarif_report
from skillguard.reporting.terminal_report import render_terminal_report
from skillguard.rules.registry import get_rule, list_rule_metas
from skillguard.scanner.discovery import DiscoveryError
from skillguard.scanner.engine import ScanEngine

console = Console(stderr=False)
err_console = Console(stderr=True)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parse_fail_on(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        raise click.BadParameter(
            f"Invalid severity '{value}'. Choose from: " + ", ".join(s.value for s in Severity)
        ) from exc


def _should_fail(report: ScanReport, fail_on: Severity | None) -> bool:
    if fail_on is None:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for f in report.all_findings:
        if SEVERITY_ORDER[f.severity] >= threshold:
            return True
    risk_as_sev = {
        RiskLevel.CRITICAL: Severity.CRITICAL,
        RiskLevel.HIGH: Severity.HIGH,
        RiskLevel.MEDIUM: Severity.MEDIUM,
        RiskLevel.LOW: Severity.LOW,
        RiskLevel.INFORMATIONAL: Severity.INFORMATIONAL,
    }
    return SEVERITY_ORDER[risk_as_sev[report.overall_risk]] >= threshold


def _should_fail_with_baseline(
    report: ScanReport,
    fail_on: Severity | None,
    suppression: object | None,
) -> bool:
    if fail_on is None:
        return False
    if suppression is None:
        return _should_fail(report, fail_on)
    active = max_active_severity(report, suppression)  # type: ignore[arg-type]
    if active is None:
        return False
    return SEVERITY_ORDER[active] >= SEVERITY_ORDER[fail_on]


@click.group()
@click.version_option(__version__, prog_name="skillguard")
def main() -> None:
    """SkillGuard — security scanner for AI Agent Skills."""


@main.command("version")
def version_cmd() -> None:
    """Print SkillGuard version."""
    click.echo(f"skillguard {__version__}")


@main.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json", "sarif"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write report to file.")
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=None,
    help="Exit 1 if findings at or above this severity exist.",
)
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path))
@click.option("--exclude", multiple=True, help="Additional exclude glob (repeatable).")
@click.option("--disable-rule", multiple=True, help="Disable rule ID (repeatable).")
@click.option("--sandbox", is_flag=True, help="Opt-in Docker sandbox dynamic analysis.")
@click.option(
    "--sandbox-strict",
    is_flag=True,
    help="Require digest-pinned sandbox image (fail-closed).",
)
@click.option(
    "--sandbox-image",
    default=None,
    help="Sandbox image reference (prefer repo@sha256:…).",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Baseline file for accepted findings (annotate only; does not rewrite findings).",
)
@click.option(
    "--audit-manifest",
    type=click.Path(path_type=Path),
    default=None,
    help="Write reproducible audit manifest(s) to this path (or directory).",
)
@click.option("--skill-version", default=None, help="Optional skill version for audit manifest.")
@click.option("--source-commit", default=None, help="Optional source commit for audit manifest.")
@click.option("--no-quality", is_flag=True, help="Skip quality evaluation.")
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def scan_cmd(
    path: Path,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    config_path: Path | None,
    exclude: tuple[str, ...],
    disable_rule: tuple[str, ...],
    sandbox: bool,
    sandbox_strict: bool,
    sandbox_image: str | None,
    baseline_path: Path | None,
    audit_manifest: Path | None,
    skill_version: str | None,
    source_commit: str | None,
    no_quality: bool,
    quiet: bool,
) -> None:
    """Scan a skill or a directory of skills."""
    cfg = ScanConfig.from_file(config_path) if config_path else ScanConfig()
    if exclude:
        cfg.exclude_globs = list(cfg.exclude_globs) + list(exclude)
    if disable_rule:
        cfg.rules_disabled = list(cfg.rules_disabled) + list(disable_rule)
    cfg.enable_sandbox = sandbox
    cfg.sandbox_strict_image = sandbox_strict or cfg.sandbox_strict_image
    if sandbox_image:
        cfg.sandbox_image = sandbox_image
    if baseline_path:
        cfg.baseline_path = str(baseline_path)
    cfg.include_quality = not no_quality
    cfg.show_progress = not quiet
    cfg.fail_on = _parse_fail_on(fail_on)

    if cfg.show_progress and fmt == "terminal" and output is None:
        err_console.print(f"[dim]Scanning {path}…[/dim]")

    engine = ScanEngine(cfg)
    try:
        report = engine.scan_path(path)
    except DiscoveryError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(EXIT_ERROR)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Scan failed:[/red] {exc}")
        sys.exit(EXIT_ERROR)

    suppression = None
    if cfg.baseline_path:
        try:
            baseline = load_baseline(Path(cfg.baseline_path))
            report, suppression = annotate_report(report, baseline)
            if suppression.expired:
                err_console.print(
                    f"[yellow]Baseline: {len(suppression.expired)} expired acceptance(s)[/yellow]"
                )
            if suppression.blocked_critical:
                err_console.print(
                    f"[yellow]Baseline: {len(suppression.blocked_critical)} "
                    "critical suppression(s) blocked[/yellow]"
                )
            if suppression.suppressed:
                err_console.print(
                    f"[dim]Baseline: {len(suppression.suppressed)} finding(s) suppressed "
                    "(still present in report)[/dim]"
                )
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"[red]Baseline error:[/red] {exc}")
            sys.exit(EXIT_ERROR)

    if audit_manifest is not None:
        manifests = build_audit_manifest(
            report,
            config_dict=cfg.model_dump(mode="json"),
            skill_version=skill_version,
            source_commit=source_commit,
            suppression=suppression.model_dump(mode="json") if suppression else None,
        )
        if len(manifests) == 1 and audit_manifest.suffix == ".json":
            write_audit_manifest(manifests[0], audit_manifest)
            err_console.print(f"[dim]Wrote audit manifest {audit_manifest}[/dim]")
        else:
            audit_manifest.mkdir(parents=True, exist_ok=True)
            for m in manifests:
                safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in m.skill_identifier)
                out_path = audit_manifest / f"audit-{safe}.json"
                write_audit_manifest(m, out_path)
            err_console.print(
                f"[dim]Wrote {len(manifests)} audit manifest(s) to {audit_manifest}[/dim]"
            )

    if fmt == "json":
        text = write_json_report(report, output)
        if output is None:
            click.echo(text)
        if suppression is not None and output is not None:
            side = output.with_suffix(".suppression.json")
            side.write_text(
                json.dumps(suppression.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    elif fmt == "sarif":
        text = write_sarif_report(report, output)
        if output is None:
            click.echo(text)
    else:
        if output is not None:
            write_json_report(report, output)
        render_terminal_report(report, console=console)

    if not report.skills:
        err_console.print("[yellow]No skills found at target path.[/yellow]")
        sys.exit(EXIT_ERROR)

    if _should_fail_with_baseline(report, cfg.fail_on, suppression):
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_OK)


@main.command("compare")
@click.argument("old_report", type=click.Path(exists=True, path_type=Path))
@click.argument("new_report", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write compare JSON.")
@click.option(
    "--fail-on-introduced",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default="high",
    show_default=True,
    help="Fail if newly introduced findings meet this severity.",
)
@click.option(
    "--no-fail-on-risk-increase",
    is_flag=True,
    help="Do not fail when overall risk score increases.",
)
@click.option(
    "--fail-on-new-scripts",
    is_flag=True,
    help="Fail when new script files appear between reports.",
)
@click.option("--json", "as_json", is_flag=True, help="Print JSON to stdout.")
def compare_cmd(
    old_report: Path,
    new_report: Path,
    output: Path | None,
    fail_on_introduced: str,
    no_fail_on_risk_increase: bool,
    fail_on_new_scripts: bool,
    as_json: bool,
) -> None:
    """Compare two SkillGuard JSON reports for security regression."""
    try:
        result = compare_reports(old_report, new_report)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Compare failed:[/red] {exc}")
        sys.exit(EXIT_ERROR)

    payload = result.to_dict()
    if output is not None:
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        console.print(result.format_terminal())

    fail = should_fail_compare(
        result,
        fail_on_introduced=_parse_fail_on(fail_on_introduced),
        fail_on_risk_increase=not no_fail_on_risk_increase,
        fail_on_new_scripts=fail_on_new_scripts,
    )
    sys.exit(EXIT_FINDINGS if fail else EXIT_OK)


@main.group("baseline")
def baseline_group() -> None:
    """Manage accepted-finding baselines (suppressions are annotations only)."""


@baseline_group.command("init")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=Path(".skillguard-baseline.json"),
    show_default=True,
)
@click.option("--allow-critical", is_flag=True, help="Allow critical suppressions (discouraged).")
def baseline_init(output: Path, allow_critical: bool) -> None:
    """Create an empty baseline file."""
    if output.exists():
        err_console.print(f"[red]Refusing to overwrite existing baseline:[/red] {output}")
        sys.exit(EXIT_ERROR)
    bl = Baseline(allow_critical_suppressions=allow_critical)
    save_baseline(bl, output)
    console.print(f"Created empty baseline at {output}")
    sys.exit(EXIT_OK)


@baseline_group.command("accept")
@click.argument("report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Baseline file to update.",
)
@click.option("--fingerprint", required=True, help="Finding fingerprint to accept.")
@click.option("--justification", required=True, help="Why this finding is accepted.")
@click.option("--accepted-by", default=None)
@click.option("--expires-days", type=int, default=90, show_default=True)
def baseline_accept(
    report: Path,
    baseline_path: Path,
    fingerprint: str,
    justification: str,
    accepted_by: str | None,
    expires_days: int,
) -> None:
    """Accept a known finding into the baseline (does not rewrite the scan report)."""
    data = json.loads(report.read_text(encoding="utf-8"))
    bl = load_baseline(baseline_path) if baseline_path.exists() else Baseline()

    target: dict[str, object] | None = None
    skill_name: str | None = None
    for skill in data.get("skills") or []:
        for finding in skill.get("findings") or []:
            from skillguard.fingerprint import fingerprint_from_finding_dict

            if not isinstance(finding, dict):
                continue
            fp = fingerprint_from_finding_dict(finding)
            if fp == fingerprint or finding.get("fingerprint") == fingerprint:
                target = finding
                sn = skill.get("skill_name")
                skill_name = sn if isinstance(sn, str) else None
                break
        if target:
            break
    if target is None:
        err_console.print(f"[red]Fingerprint not found in report:[/red] {fingerprint}")
        sys.exit(EXIT_ERROR)

    try:
        entry = accept_finding(
            bl,
            target,
            justification=justification,
            accepted_by=accepted_by,
            expires_days=expires_days,
            skill_name=skill_name,
        )
    except ValueError as exc:
        err_console.print(f"[red]Accept refused:[/red] {exc}")
        sys.exit(EXIT_ERROR)

    save_baseline(bl, baseline_path)
    console.print(f"Accepted {entry.fingerprint} ({entry.rule_id}) into {baseline_path}")
    sys.exit(EXIT_OK)


@baseline_group.command("show")
@click.argument("baseline_path", type=click.Path(exists=True, path_type=Path))
def baseline_show(baseline_path: Path) -> None:
    """Show baseline entries."""
    bl = load_baseline(baseline_path)
    table = Table(title=f"Baseline ({len(bl.entries)} entries)")
    table.add_column("Fingerprint")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Expires")
    table.add_column("Justification")
    for e in bl.entries:
        table.add_row(
            e.fingerprint[:12],
            e.rule_id,
            e.severity,
            e.expires_at.isoformat() if e.expires_at else "never",
            e.justification[:60],
        )
    console.print(table)
    console.print(f"allow_critical_suppressions={bl.allow_critical_suppressions}")
    sys.exit(EXIT_OK)


@main.command("audit")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    required=True,
    help="Output path or directory for audit manifest(s).",
)
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path))
@click.option("--skill-version", default=None)
@click.option("--source-commit", default=None)
@click.option("--baseline", "baseline_path", type=click.Path(exists=True, path_type=Path))
@click.option("--quiet", is_flag=True)
def audit_cmd(
    path: Path,
    output: Path,
    config_path: Path | None,
    skill_version: str | None,
    source_commit: str | None,
    baseline_path: Path | None,
    quiet: bool,
) -> None:
    """Generate a reproducible audit manifest for a skill path."""
    cfg = ScanConfig.from_file(config_path) if config_path else ScanConfig()
    cfg.show_progress = not quiet
    engine = ScanEngine(cfg)
    try:
        report = engine.scan_path(path)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Audit scan failed:[/red] {exc}")
        sys.exit(EXIT_ERROR)

    suppression_dict = None
    if baseline_path:
        bl = load_baseline(baseline_path)
        report, suppression = annotate_report(report, bl)
        suppression_dict = suppression.model_dump(mode="json")

    manifests = build_audit_manifest(
        report,
        config_dict=cfg.model_dump(mode="json"),
        skill_version=skill_version,
        source_commit=source_commit,
        suppression=suppression_dict,
    )
    if not manifests:
        err_console.print("[yellow]No skills found.[/yellow]")
        sys.exit(EXIT_ERROR)

    if len(manifests) == 1 and output.suffix == ".json":
        text = write_audit_manifest(manifests[0], output)
        if not quiet:
            console.print(
                f"Wrote audit manifest ({manifests[0].content_digest()[:16]}…) → {output}"
            )
            console.print(f"Bytes: {len(text)}")
    else:
        output.mkdir(parents=True, exist_ok=True)
        for m in manifests:
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in m.skill_identifier)
            out_path = output / f"audit-{safe}.json"
            write_audit_manifest(m, out_path)
        if not quiet:
            console.print(f"Wrote {len(manifests)} audit manifest(s) to {output}")
    sys.exit(EXIT_OK)


@main.group("rules")
def rules_group() -> None:
    """Inspect detection rules."""


@rules_group.command("list")
def rules_list() -> None:
    """List all registered detection rules."""
    table = Table(title="SkillGuard Rules")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Name")
    for meta in list_rule_metas():
        table.add_row(meta["id"], meta["severity"], meta["category"], meta["name"])
    console.print(table)


@rules_group.command("show")
@click.argument("rule_id")
def rules_show(rule_id: str) -> None:
    """Show details for a rule ID."""
    rule = get_rule(rule_id)
    if rule is None:
        err_console.print(f"[red]Unknown rule:[/red] {rule_id}")
        sys.exit(EXIT_ERROR)
    m = rule.meta
    console.print(f"[bold]{m.id}[/bold] — {m.name}")
    console.print(f"Severity: {m.severity.value}")
    console.print(f"Category: {m.category.value}")
    console.print(f"Description: {m.description}")
    console.print(f"Remediation: {m.remediation}")
    if m.tags:
        console.print(f"Tags: {', '.join(m.tags)}")


@main.group("benchmark")
def benchmark_group() -> None:
    """Run detection quality benchmarks."""


@benchmark_group.command("run")
@click.option(
    "--fixtures",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Fixture root (default: tests/fixtures).",
)
@click.option(
    "--dataset",
    type=click.Choice(["auto", "adversarial", "legacy"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Which labeled dataset to score.",
)
@click.option("--json-out", type=click.Path(path_type=Path), default=None)
def benchmark_run(
    fixtures: Path | None,
    dataset: str,
    json_out: Path | None,
) -> None:
    """Run benchmark corpus and print metrics."""
    from skillguard.evaluation.benchmark import (
        run_benchmark,
        run_legacy_benchmark,
        run_manifest_benchmark,
    )

    root = fixtures or Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    if dataset == "adversarial":
        result = run_manifest_benchmark(root / "adversarial")
    elif dataset == "legacy":
        result = run_legacy_benchmark(root)
    else:
        result = run_benchmark(root)
    console.print(result.format_terminal())
    if json_out:
        json_out.write_text(result.to_json(), encoding="utf-8")
        console.print(f"Wrote {json_out}")
    sys.exit(EXIT_OK)


@benchmark_group.command("compare-tools")
@click.option(
    "--fixtures",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Fixture root (default: tests/fixtures).",
)
@click.option("--limit", type=int, default=None, help="Limit fixtures (smoke).")
@click.option("--json-out", type=click.Path(path_type=Path), default=None)
def benchmark_compare_tools(
    fixtures: Path | None,
    limit: int | None,
    json_out: Path | None,
) -> None:
    """Reproducible third-party comparison harness (no superiority claims)."""
    from skillguard.evaluation.comparison import run_comparison

    root = fixtures or Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    report = run_comparison(root, limit=limit)
    console.print(report.format_terminal())
    if json_out:
        json_out.write_text(report.to_json(), encoding="utf-8")
        console.print(f"Wrote {json_out}")
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
