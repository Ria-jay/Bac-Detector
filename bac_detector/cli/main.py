"""
BAC Detector CLI entrypoint.

All commands are defined here using Typer. Each command validates
its inputs early and exits cleanly on error.

Usage:
    bacdet scan          --config config.yaml [--dry-run] [--output-dir ./results]
    bacdet discover      --config config.yaml [--output endpoints.json]
    bacdet report        --input findings.json --format md [--output report.md]
    bacdet validate-demo
    bacdet version
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bac_detector import __version__
from bac_detector.config.loader import ScanConfig, load_config
from bac_detector.models.scan_result import ScanResult, ScanStatus
from bac_detector.utils.logging import configure_logging, get_logger

app = typer.Typer(
    name="bacdet",
    help=(
        "BAC Detector — Automated Broken Access Control testing tool.\n\n"
        "[bold red]For authorized security testing only.[/bold red]\n"
        "Use only against applications you own or have explicit written permission to test."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)

console = Console(stderr=False)
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config_or_exit(config_path: str) -> ScanConfig:
    """Load and validate config, print a clean error and exit on failure."""
    try:
        return load_config(config_path)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        err_console.print(f"[bold red]Config validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


def _print_authorized_use_banner() -> None:
    """Remind the user this tool is for authorized testing only."""
    console.print(
        Panel(
            "[bold yellow]AUTHORIZED USE ONLY[/bold yellow]\n"
            "Run this tool only against applications you own or have\n"
            "explicit written permission to test.\n"
            "Unauthorized scanning may be illegal.",
            border_style="yellow",
            expand=False,
        )
    )


def _require(value: Optional[str], flag: str) -> str:
    """Exit with a clean error if a required option was not supplied."""
    if not value:
        err_console.print(
            f"[bold red]Error:[/bold red] Missing required option '{flag}'."
        )
        raise typer.Exit(code=1)
    return value


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML configuration file.",
        show_default=False,
    ),
    output_dir: Optional[str] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory for output files. Overrides config value.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print requests without sending them.",
    ),
) -> None:
    """
    Run a full BAC scan: discover endpoints, replay across identities, detect issues.

    Reads target, identity profiles, and test settings from CONFIG.
    Writes a JSON findings file and a Markdown pentest report to the output directory.
    Graph analysis runs automatically when graph_analysis.enabled is true in config.
    """
    config_path = _require(config_path, "--config")
    _print_authorized_use_banner()

    config = _load_config_or_exit(config_path)
    configure_logging(config.log_config.level, config.log_config.json_logs)
    log = get_logger(__name__)

    # Apply CLI overrides — ScanConfig sub-models are not frozen
    if output_dir:
        config.output.output_dir = output_dir

    # Resolve effective dry-run: CLI flag takes priority over config file value
    effective_dry_run = dry_run or config.safety.dry_run
    if effective_dry_run:
        config.safety.dry_run = True

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    console.print(f"\n[bold]Target:[/bold] {config.target.base_url}")
    console.print(f"[bold]Identities:[/bold] {', '.join(i.name for i in config.identities)}")
    sources = []
    if config.target.openapi_url:
        sources.append(f"OpenAPI ({config.target.openapi_url})")
    if config.target.endpoint_list_path:
        sources.append(f"endpoint list ({config.target.endpoint_list_path})")
    console.print(f"[bold]Discovery:[/bold] {', '.join(sources) or 'none configured'}")

    from bac_detector.reporters.writer import resolve_output_paths
    resolve_output_paths(config.output)
    console.print(f"[bold]Output:[/bold]    {config.output.output_dir}/")

    if config.graph_analysis.enabled:
        console.print("[bold]Graph analysis:[/bold] enabled")
    if effective_dry_run:
        console.print("[yellow]DRY RUN — requests will not be sent[/yellow]")
    console.print()

    log.info(
        "scan_started",
        scan_id=scan_id,
        target=config.target.base_url,
        identities=[i.name for i in config.identities],
        dry_run=effective_dry_run,
        graph_analysis=config.graph_analysis.enabled,
    )

    # --- Phase 2: Discovery ---
    from bac_detector.discovery.runner import run_discovery

    try:
        inventory = run_discovery(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[bold red]Discovery failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Discovery complete:[/green] {inventory.total} endpoints "
        f"({', '.join(inventory.sources_used)})"
    )

    # --- Phase 3: Replay ---
    from bac_detector.replay.runner import run_replay
    from bac_detector.analyzers.matrix import build_matrix
    from bac_detector.analyzers.baseline import build_baselines

    console.print(
        f"[bold]Replaying[/bold] across {len(config.identities)} identities "
        f"(budget: {config.throttle.request_budget} requests, "
        f"{config.throttle.requests_per_second} req/s)..."
    )

    responses, replay_summary = run_replay(inventory, config)
    matrix = build_matrix(responses)
    baselines = build_baselines(matrix, config.identity_profiles)

    console.print(
        f"[green]Replay complete:[/green] {replay_summary.total_sent} requests sent"
        + (f", {replay_summary.total_errors} errors" if replay_summary.total_errors else "")
        + (f" [yellow](budget exhausted)[/yellow]" if replay_summary.budget_exhausted else "")
    )

    # --- Phase 4: Detection ---
    from bac_detector.detectors.runner import run_detection

    findings = run_detection(matrix, baselines, config.identity_profiles)

    confirmed = sum(1 for f in findings if f.confidence.value == "confirmed")
    potential = sum(1 for f in findings if f.confidence.value == "potential")
    console.print(
        f"[green]Detection complete:[/green] {len(findings)} finding(s) "
        f"({confirmed} confirmed, {potential} potential)"
    )

    # --- Phase 4G: Graph analysis (optional) ---
    if config.graph_analysis.enabled and not effective_dry_run:
        try:
            from bac_detector.graph.builder import build_graph
            from bac_detector.graph.service import run_graph_analysis

            graph = build_graph(matrix, inventory, config.identity_profiles)
            graph_findings = run_graph_analysis(graph, config.graph_analysis)

            if graph_findings:
                findings = findings + graph_findings
                g_confirmed = sum(1 for f in graph_findings if f.confidence.value == "confirmed")
                g_potential = sum(1 for f in graph_findings if f.confidence.value == "potential")
                console.print(
                    f"[green]Graph analysis:[/green] {len(graph_findings)} additional finding(s) "
                    f"({g_confirmed} confirmed, {g_potential} potential)"
                )
            else:
                console.print("[green]Graph analysis:[/green] no additional findings")

        except Exception as exc:
            err_console.print(
                f"[yellow]Warning: graph analysis failed (findings from Phase 4 preserved): "
                f"{exc}[/yellow]"
            )
            log.warning("graph_analysis_failed", error=str(exc))

    result = ScanResult(
        scan_id=scan_id,
        target=config.target.base_url,
        status=ScanStatus.COMPLETED,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        endpoints_discovered=inventory.total,
        discovery_sources_used=inventory.sources_used,
        endpoints=[ep.model_dump() for ep in inventory.endpoints],
        requests_made=replay_summary.total_sent,
        requests_errored=replay_summary.total_errors,
        identities_tested=[i.name for i in config.identities],
        raw_responses=[r.model_dump() for r in responses],
        findings=findings,
        auth_matrix=matrix.to_status_summary(),
        warnings=["DRY RUN — no requests were sent."] if effective_dry_run else [],
    )

    # --- Phase 5: Reporting ---
    from bac_detector.reporters.terminal import print_scan_summary
    from bac_detector.reporters.writer import write_all_reports

    print_scan_summary(result, out=console)

    if not effective_dry_run:
        try:
            paths = write_all_reports(result, config.output)
            console.print()
            console.print("[green]Reports written:[/green]")
            console.print(f"  JSON:     {paths.json_path}")
            console.print(f"  Markdown: {paths.markdown_path}")
        except OSError as exc:
            err_console.print(f"[yellow]Warning: could not write reports: {exc}[/yellow]")

    log.info(
        "scan_finished",
        scan_id=result.scan_id,
        endpoints=inventory.total,
        requests=replay_summary.total_sent,
        findings=len(findings),
        matrix_cells=matrix.total_cells,
    )


@app.command()
def discover(
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML configuration file.",
        show_default=False,
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write endpoint inventory to this JSON file.",
    ),
) -> None:
    """
    Run endpoint discovery only and print the inventory.

    Useful for auditing discovered endpoints before running a full scan.
    Loads from OpenAPI spec or endpoint list per config.
    """
    import json as _json

    config_path = _require(config_path, "--config")
    config = _load_config_or_exit(config_path)
    configure_logging(config.log_config.level, config.log_config.json_logs)
    log = get_logger(__name__)

    console.print(f"[bold]Discovery target:[/bold] {config.effective_api_base_url}")
    if config.target.openapi_url:
        console.print(f"[bold]OpenAPI spec:[/bold]   {config.target.openapi_url}")
    if config.target.endpoint_list_path:
        console.print(f"[bold]Endpoint list:[/bold]  {config.target.endpoint_list_path}")
    console.print()

    from bac_detector.discovery.runner import run_discovery

    try:
        inventory = run_discovery(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[bold red]Discovery failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(
        title=f"Endpoint Inventory ({inventory.total} endpoints)",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
    )
    table.add_column("Method", style="bold cyan", width=8)
    table.add_column("Path")
    table.add_column("Params", width=6, justify="right")
    table.add_column("IDOR?", width=6)
    table.add_column("Source", width=14)

    for ep in sorted(inventory.endpoints, key=lambda e: (e.path, e.method.value)):
        has_idor = "✓" if ep.object_id_params else ""
        table.add_row(
            ep.method.value,
            ep.path,
            str(len(ep.parameters)),
            f"[green]{has_idor}[/green]",
            ep.source,
        )

    console.print(table)
    console.print()
    for line in inventory.summary_lines():
        console.print(f"  {line}")

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = [ep.model_dump() for ep in inventory.endpoints]
        out_path.write_text(_json.dumps(serialized, indent=2, default=str))
        console.print(f"\n[green]Inventory written to:[/green] {out_path}")
        log.info("discover_output_written", path=str(out_path), count=len(serialized))


@app.command()
def report(
    input_path: Optional[str] = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to a findings.json file produced by a previous scan.",
        show_default=False,
    ),
    fmt: str = typer.Option(
        "md",
        "--format",
        "-f",
        help="Output format: 'md' (Markdown) or 'terminal'.",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. Prints to stdout if not specified.",
    ),
) -> None:
    """
    Generate a report from an existing findings.json file.

    Re-renders a previous scan's findings as Markdown or terminal output
    without re-running the scan.

    Examples:

        bacdet report --input results/findings.json --format md

        bacdet report --input results/findings.json --format md --output report.md

        bacdet report --input results/findings.json --format terminal
    """
    input_path = _require(input_path, "--input")
    path = Path(input_path)
    if not path.exists():
        err_console.print(f"[bold red]Error:[/bold red] Input file not found: {path}")
        raise typer.Exit(code=1)

    if fmt not in ("md", "terminal"):
        err_console.print(
            f"[bold red]Unknown format:[/bold red] {fmt!r}. Use 'md' or 'terminal'."
        )
        raise typer.Exit(code=1)

    try:
        from bac_detector.reporters.json_reporter import load_scan_result
        result = load_scan_result(path)
    except Exception as exc:
        err_console.print(f"[bold red]Failed to load findings:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if fmt == "terminal":
        from bac_detector.reporters.terminal import print_scan_summary
        print_scan_summary(result, out=console)
    else:
        from bac_detector.reporters.markdown_reporter import build_markdown_report
        md = build_markdown_report(result)
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(md, encoding="utf-8")
            console.print(f"[green]Markdown report written to:[/green] {out_path}")
        else:
            print(md)


@app.command(name="validate-demo")
def validate_demo() -> None:
    """
    Run the BAC detector against the local intentionally-vulnerable demo app.

    Starts the demo FastAPI app, runs a full scan, and verifies that the
    three known broken access control flaws are detected and the public
    /health endpoint is not incorrectly flagged.
    """
    import socket
    import threading
    import time

    import uvicorn

    from bac_detector.config.loader import (
        IdentityConfig, OutputConfig, SafetyConfig, TargetConfig, ThrottleConfig,
    )
    from bac_detector.models.identity import AuthMechanism
    from bac_detector.analyzers.baseline import build_baselines
    from bac_detector.analyzers.matrix import build_matrix
    from bac_detector.detectors.runner import run_detection
    from bac_detector.discovery.runner import run_discovery
    from bac_detector.replay.runner import run_replay

    # ── Find a free port ────────────────────────────────────────────────────
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    # ── Start demo app in background thread ─────────────────────────────────
    class _Server(uvicorn.Server):
        def install_signal_handlers(self): pass

    uconfig = uvicorn.Config(
        "demo_app.app:app", host="127.0.0.1", port=port, log_level="error"
    )
    server = _Server(uconfig)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)

    console.print(f"\n[bold]Demo app:[/bold] {base_url}")
    console.print("[bold]Running end-to-end scan...[/bold]\n")

    # ── Build config ─────────────────────────────────────────────────────────
    import tempfile
    tmpdir = tempfile.mkdtemp()
    config = ScanConfig(
        target=TargetConfig(
            base_url=base_url,
            openapi_url=f"{base_url}/openapi.json",
        ),
        identities=[
            IdentityConfig(name="alice", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="token-alice",
                owned_object_ids=["1"]),
            IdentityConfig(name="bob", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="token-bob",
                owned_object_ids=["2"]),
            IdentityConfig(name="admin", role="admin",
                auth_mechanism=AuthMechanism.BEARER, token="token-admin",
                owned_object_ids=["3"]),
        ],
        throttle=ThrottleConfig(requests_per_second=20.0, request_budget=500),
        safety=SafetyConfig(dry_run=False, read_only=True, verify_ssl=False),
        output=OutputConfig(output_dir=tmpdir, overwrite=True),
    )

    # ── Run pipeline ─────────────────────────────────────────────────────────
    try:
        inventory = run_discovery(config)
        responses, _ = run_replay(inventory, config)
        matrix = build_matrix(responses)
        baselines = build_baselines(matrix, config.identity_profiles)
        findings = run_detection(matrix, baselines, config.identity_profiles)
    finally:
        server.should_exit = True

    # ── Assertions ───────────────────────────────────────────────────────────
    passed, failed = [], []

    def _check(condition: bool, label: str) -> None:
        (passed if condition else failed).append(label)

    idor     = [f for f in findings if f.category == "IDOR"]
    vertical = [f for f in findings if f.category == "vertical_escalation"]
    horizont = [f for f in findings if f.category == "horizontal_escalation"]
    health_f = [f for f in findings if "health" in f.endpoint_key]

    _check(len(idor) >= 1,     "IDOR detected on /users/{user_id}")
    _check(len(vertical) >= 1, "Vertical escalation detected on /admin/*")
    _check(len(horizont) >= 1, "Horizontal escalation detected on /me/profile")
    _check(len(health_f) == 0, "/health NOT flagged (negative control)")

    from bac_detector.reporters.terminal import print_scan_summary
    result = ScanResult(
        scan_id="validate-demo",
        target=base_url,
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        endpoints_discovered=inventory.total,
        identities_tested=[i.name for i in config.identities],
        findings=findings,
        auth_matrix=matrix.to_status_summary(),
    )
    print_scan_summary(result, out=console)

    console.print()
    for label in passed:
        console.print(f"  [green]✓[/green] {label}")
    for label in failed:
        console.print(f"  [red]✗[/red] {label}")

    if failed:
        console.print(f"\n[bold red]{len(failed)} assertion(s) failed.[/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print(f"\n[bold green]All {len(passed)} assertions passed.[/bold green]")


@app.command()
def version() -> None:
    """Print the BAC Detector version and exit."""
    console.print(f"bacdet {__version__}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entrypoint called by the bacdet script."""
    app()


if __name__ == "__main__":
    main()
