"""
JSON findings reporter.

Serializes the complete ScanResult to a structured JSON file.
The JSON output is machine-readable and suitable for integration
with other tools (ticket trackers, CI pipelines, dashboards).

File structure:
  {
    "schema_version": "1.0",
    "tool": "bac-detector",
    "summary": { ... human-readable counts ... },
    "scan_result": { ... full ScanResult model dump for round-trip loading ... },
  }

The `scan_result` key contains the complete ScanResult serialization so
that `bacdet report --input findings.json` can reload it via
ScanResult.model_validate(data["scan_result"]) with all fields intact.

Raw response bodies are stripped from scan_result.raw_responses to keep
the file size reasonable — findings contain evidence snippets.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from bac_detector.models.scan_result import ScanResult
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


def write_json_report(result: ScanResult, output_path: Path) -> None:
    """
    Write a JSON findings report to the given path.

    The file embeds the full ScanResult so that it can be reloaded by
    `bacdet report` without losing any metadata fields.

    Args:
        result: The completed ScanResult.
        output_path: Where to write the JSON file.

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = _build_payload(result)
    text = json.dumps(payload, indent=2, default=_json_default)
    output_path.write_text(text, encoding="utf-8")

    log.info(
        "json_report_written",
        path=str(output_path),
        findings=len(result.findings),
        bytes=len(text),
    )


def load_scan_result(input_path: Path) -> ScanResult:
    """
    Load a ScanResult from a findings.json file written by write_json_report().

    Handles both the current schema (with a "scan_result" key) and a plain
    ScanResult dump (for forward/backward compatibility).

    Args:
        input_path: Path to a findings.json file.

    Returns:
        Populated ScanResult.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed or validated.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"Findings file not found: {input_path}")

    try:
        with input_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {input_path}: {exc}") from exc

    # Prefer the embedded full scan_result if present (written by this reporter)
    if isinstance(raw, dict) and "scan_result" in raw:
        return ScanResult.model_validate(raw["scan_result"])

    # Fall back to treating the whole file as a ScanResult dump
    return ScanResult.model_validate(raw)


def _build_payload(result: ScanResult) -> dict:
    """
    Build the complete JSON payload from a ScanResult.

    Contains:
      - Human-readable summary block (counts, metadata at a glance)
      - Full scan_result dump for round-trip loading (without raw_responses)
    """
    duration = result.duration_seconds

    # Build the full ScanResult dump, stripping raw_responses to save space
    scan_result_dict = result.model_dump(mode="json")
    scan_result_dict.pop("raw_responses", None)

    return {
        "schema_version": "1.0",
        "tool": "bac-detector",
        "summary": {
            "scan_id": result.scan_id,
            "target": result.target,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "duration_seconds": round(duration, 2) if duration is not None else None,
            "endpoints_discovered": result.endpoints_discovered,
            "discovery_sources": result.discovery_sources_used,
            "requests_made": result.requests_made,
            "requests_errored": result.requests_errored,
            "identities_tested": result.identities_tested,
            "total_findings": len(result.findings),
            "findings_by_severity": result.finding_counts_by_severity,
            "findings_by_category": _counts_by_category(result.findings),
            "confirmed_findings": len(result.confirmed_findings),
            "potential_findings": sum(
                1 for f in result.findings if f.confidence.value == "potential"
            ),
        },
        "scan_result": scan_result_dict,
    }


def _counts_by_category(findings) -> dict[str, int]:
    """Return a dict of finding counts keyed by category string."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return dict(sorted(counts.items()))


def _json_default(obj):
    """JSON serializer fallback for non-standard types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
