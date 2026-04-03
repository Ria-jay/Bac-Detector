"""
Terminal summary reporter.

Prints a Rich-formatted scan summary to stdout. This is the immediate
feedback a pentester sees after a scan completes — a high-level overview
designed to be read in 15 seconds.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bac_detector.models.finding import Confidence, Finding
from bac_detector.models.scan_result import ScanResult

console = Console()

# Severity display: color, label
_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "critical": ("bold red", "CRITICAL"),
    "high":     ("red",      "HIGH"),
    "medium":   ("yellow",   "MEDIUM"),
    "low":      ("cyan",     "LOW"),
    "info":     ("dim",      "INFO"),
}

# Confidence display
_CONFIDENCE_STYLE: dict[str, str] = {
    "confirmed": "bold green",
    "potential": "yellow",
    "fp_risk":   "dim",
}


def print_scan_summary(result: ScanResult, out: Console | None = None) -> None:
    """
    Print a full terminal summary of a completed scan.

    Includes: scan metadata, finding counts, authorization matrix,
    and a per-finding table.

    Args:
        result: The completed ScanResult.
        out: Console to write to (defaults to stdout console).
    """
    c = out or console
    duration = result.duration_seconds
    duration_str = f"{duration:.1f}s" if duration is not None else "—"

    confirmed = sum(1 for f in result.findings if f.confidence == Confidence.CONFIRMED)
    potential = sum(1 for f in result.findings if f.confidence == Confidence.POTENTIAL)

    summary_lines = [
        f"[bold]Target:[/bold]      {result.target}",
        f"[bold]Scan ID:[/bold]     {result.scan_id}",
        f"[bold]Duration:[/bold]    {duration_str}",
        f"[bold]Endpoints:[/bold]   {result.endpoints_discovered}",
        f"[bold]Requests:[/bold]    {result.requests_made} sent"
        + (f", {result.requests_errored} errored" if result.requests_errored else ""),
        f"[bold]Identities:[/bold]  {', '.join(result.identities_tested)}",
        f"[bold]Findings:[/bold]    {len(result.findings)} total "
        f"({confirmed} confirmed, {potential} potential)",
    ]

    c.print()
    c.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold blue]BAC Detector — Scan Complete[/bold blue]",
            border_style="blue",
            expand=False,
        )
    )

    if result.findings:
        _print_findings_table(result.findings, c)
    else:
        c.print("\n[green]No findings detected.[/green]")

    if result.auth_matrix:
        _print_matrix_table(result.auth_matrix, c)

    if result.warnings:
        c.print()
        for w in result.warnings:
            c.print(f"  [yellow]⚠ {w}[/yellow]")

    if result.errors:
        c.print(f"\n[yellow]Errors during scan: {len(result.errors)}[/yellow]")
        for err in result.errors[:5]:
            c.print(f"  [dim]• {err}[/dim]")
        if len(result.errors) > 5:
            c.print(f"  [dim]... and {len(result.errors) - 5} more[/dim]")


def _print_findings_table(findings: list[Finding], c: Console) -> None:
    """Print a compact findings table."""
    c.print()
    table = Table(
        title=f"Findings ({len(findings)} total)",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=False,
    )
    table.add_column("Severity",   width=10, style="bold")
    table.add_column("Confidence", width=12)
    table.add_column("Category",   width=22)
    table.add_column("Endpoint")
    table.add_column("Identities")

    for finding in findings:
        sev_style, sev_label = _SEVERITY_STYLE.get(
            finding.severity.value, ("white", finding.severity.value.upper())
        )
        conf_style = _CONFIDENCE_STYLE.get(finding.confidence.value, "white")
        identities = finding.evidence.attacker_identity
        if finding.evidence.victim_identity:
            identities += f" → {finding.evidence.victim_identity}"

        table.add_row(
            f"[{sev_style}]{sev_label}[/{sev_style}]",
            f"[{conf_style}]{finding.confidence.value}[/{conf_style}]",
            finding.category,
            finding.endpoint_key,
            identities,
        )

    c.print(table)


def _print_matrix_table(
    auth_matrix: dict[str, dict[str, int]], c: Console
) -> None:
    """Print the authorization matrix as a status-code grid."""
    if not auth_matrix:
        return

    # Collect all identity names across the matrix (preserve insertion order)
    identity_names: list[str] = []
    for identity_map in auth_matrix.values():
        for name in identity_map:
            if name not in identity_names:
                identity_names.append(name)

    c.print()
    table = Table(
        title="Authorization Matrix",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=False,
    )
    table.add_column("Endpoint", no_wrap=True)
    for name in identity_names:
        table.add_column(name, width=10, justify="center")

    for ep_key, identity_map in sorted(auth_matrix.items()):
        row = [ep_key]
        for name in identity_names:
            code = identity_map.get(name, -1)
            if code == -1:
                row.append("[dim]—[/dim]")
            elif 200 <= code < 300:
                row.append(f"[green]{code}[/green]")
            elif code in (401, 403):
                row.append(f"[red]{code}[/red]")
            elif code == 0:
                row.append("[dim]err[/dim]")
            else:
                row.append(f"[yellow]{code}[/yellow]")
        table.add_row(*row)

    c.print(table)


def print_finding_detail(finding: Finding, c: Console | None = None) -> None:
    """
    Print a single finding in detailed format for interactive inspection.

    Args:
        finding: The finding to display.
        c: Console to write to.
    """
    c = c or console
    sev_style, sev_label = _SEVERITY_STYLE.get(
        finding.severity.value, ("white", finding.severity.value.upper())
    )

    c.print()
    c.print(
        Panel(
            f"[{sev_style}]{sev_label}[/{sev_style}] — {finding.confidence.value.upper()}\n"
            f"{finding.title}",
            border_style=sev_style.replace("bold ", ""),
            expand=False,
        )
    )
    c.print(f"\n[bold]Category:[/bold]   {finding.category}")
    c.print(f"[bold]Endpoint:[/bold]   {finding.endpoint_key}")
    c.print(f"\n[bold]Description[/bold]\n{finding.description}")

    if finding.reproduction_steps:
        c.print("\n[bold]Reproduction Steps[/bold]")
        for i, step in enumerate(finding.reproduction_steps, 1):
            c.print(f"  {i}. {step}")

    c.print(f"\n[bold]Why BAC[/bold]\n{finding.why_bac}")
    c.print(f"\n[bold]Business Impact[/bold]\n{finding.business_impact}")
    c.print(f"\n[bold]Remediation[/bold]\n{finding.remediation}")
