"""
Report writer — resolves output paths and orchestrates all reporters.

This is the single entry point called from the CLI scan command.
It writes both the JSON findings file and the Markdown report in one call,
respecting the overwrite setting from OutputConfig.
"""

from __future__ import annotations

from pathlib import Path

from bac_detector.config.loader import OutputConfig
from bac_detector.models.scan_result import ScanResult
from bac_detector.reporters.json_reporter import write_json_report
from bac_detector.reporters.markdown_reporter import write_markdown_report
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


class ReportPaths:
    """
    Resolved output file paths for a scan run.

    Produced by resolve_output_paths() and passed to the CLI so it can
    tell the user where files were written.
    """

    def __init__(self, json_path: Path, markdown_path: Path) -> None:
        self.json_path = json_path
        self.markdown_path = markdown_path

    def __repr__(self) -> str:
        return f"ReportPaths(json={self.json_path}, markdown={self.markdown_path})"


def write_all_reports(
    result: ScanResult,
    output_config: OutputConfig,
) -> ReportPaths:
    """
    Write all report formats (JSON + Markdown) for a completed scan.

    Respects the overwrite setting: if overwrite=False and a file already
    exists, a numbered suffix is appended (e.g. findings.1.json).

    Args:
        result: The completed ScanResult.
        output_config: Output directory and filename configuration.

    Returns:
        ReportPaths with the actual paths that were written.

    Raises:
        OSError: If output files cannot be written.
    """
    output_dir = Path(output_config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = _safe_path(
        output_dir / output_config.json_findings_filename,
        overwrite=output_config.overwrite,
    )
    md_path = _safe_path(
        output_dir / output_config.markdown_report_filename,
        overwrite=output_config.overwrite,
    )

    write_json_report(result, json_path)
    write_markdown_report(result, md_path)

    log.info(
        "reports_written",
        json=str(json_path),
        markdown=str(md_path),
    )

    return ReportPaths(json_path=json_path, markdown_path=md_path)


def resolve_output_paths(output_config: OutputConfig) -> ReportPaths:
    """
    Return the output paths that would be used without writing anything.

    Useful for displaying the expected output paths to the user before
    the scan starts.

    Args:
        output_config: Output directory and filename configuration.

    Returns:
        ReportPaths with the expected paths (may not exist yet).
    """
    output_dir = Path(output_config.output_dir)
    return ReportPaths(
        json_path=output_dir / output_config.json_findings_filename,
        markdown_path=output_dir / output_config.markdown_report_filename,
    )


def _safe_path(path: Path, overwrite: bool) -> Path:
    """
    Return a safe output path, appending a counter suffix if needed.

    If overwrite=True, the original path is returned unchanged.
    If overwrite=False and the path exists, returns path.stem + ".1" + suffix,
    incrementing until a free slot is found.

    Args:
        path: The desired output path.
        overwrite: Whether to overwrite an existing file.

    Returns:
        A path that is safe to write to.
    """
    if overwrite or not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}.{counter}{suffix}"
        if not candidate.exists():
            log.debug("report_path_renamed", original=str(path), new=str(candidate))
            return candidate
        counter += 1
