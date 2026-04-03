"""
Markdown pentest report generator.

Produces a structured Markdown document suitable for inclusion in
a real penetration test report. The document is organised as:

  1. Executive summary
  2. Scan metadata
  3. Authorization matrix
  4. Confirmed findings (full detail)
  5. Potential findings (full detail)
  6. Low-signal findings (FP_RISK — summarised only)
  7. Appendix: tested endpoints

Markdown is generated as a plain string — no external templating
library required. The output renders correctly in GitHub, GitLab,
Obsidian, and any standard Markdown renderer.
"""

from __future__ import annotations

from pathlib import Path

from bac_detector.models.finding import Confidence, Finding
from bac_detector.models.scan_result import ScanResult
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)

# Severity badge strings (Markdown doesn't have native colours, but
# these labels are clear and copy well into ticketing systems)
_SEVERITY_LABEL: dict[str, str] = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
    "low":      "🔵 Low",
    "info":     "⚪ Info",
}

_CONFIDENCE_LABEL: dict[str, str] = {
    "confirmed": "✅ Confirmed",
    "potential": "⚠️ Potential",
    "fp_risk":   "ℹ️ Low-signal",
}

# Human-friendly display names for finding categories (including graph categories).
# Falls back to the raw category string for any category not listed here.
_CATEGORY_LABEL: dict[str, str] = {
    # Standard detectors
    "IDOR":                     "IDOR / BOLA",
    "vertical_escalation":      "Vertical Privilege Escalation",
    "horizontal_escalation":    "Horizontal Privilege Escalation",
    "missing_auth_warning":     "Possible Missing Authentication",
    # Graph engine (G3)
    "graph_sibling_inconsistency":   "Inconsistent Sibling Action Protection",
    "graph_child_exposure":          "Child-Resource Exposure",
    "graph_hidden_privilege_path":   "Hidden Privilege Path",
    "graph_tenant_boundary":         "Tenant Boundary Inconsistency",
    "graph_ownership_inconsistency": "Ownership Inconsistency (BOLA)",
    "graph_partial_authorization":   "Partial Authorization Enforcement",
}


def write_markdown_report(result: ScanResult, output_path: Path) -> None:
    """
    Write a Markdown pentest report to the given path.

    Args:
        result: The completed ScanResult.
        output_path: Where to write the .md file.

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    content = build_markdown_report(result)
    output_path.write_text(content, encoding="utf-8")

    log.info(
        "markdown_report_written",
        path=str(output_path),
        findings=len(result.findings),
        bytes=len(content),
    )


def build_markdown_report(result: ScanResult) -> str:
    """
    Build the full Markdown report as a string.

    Args:
        result: The completed ScanResult.

    Returns:
        Complete Markdown document as a string.
    """
    sections: list[str] = []

    sections.append(_render_title(result))
    sections.append(_render_executive_summary(result))
    sections.append(_render_scan_metadata(result))

    if result.auth_matrix:
        sections.append(_render_auth_matrix(result))

    confirmed = [f for f in result.findings if f.confidence == Confidence.CONFIRMED]
    potential = [f for f in result.findings if f.confidence == Confidence.POTENTIAL]
    low_signal = [f for f in result.findings if f.confidence == Confidence.FP_RISK]

    if confirmed:
        sections.append(_render_findings_section(
            "Confirmed Findings",
            confirmed,
            detail_level="full",
        ))

    if potential:
        sections.append(_render_findings_section(
            "Potential Findings (Requires Verification)",
            potential,
            detail_level="full",
        ))

    if low_signal:
        sections.append(_render_findings_section(
            "Low-Signal Findings (High FP Risk)",
            low_signal,
            detail_level="summary",
        ))

    if not result.findings:
        sections.append("## Findings\n\nNo access control issues were detected during this scan.\n")

    sections.append(_render_appendix_endpoints(result))

    return "\n\n---\n\n".join(sections) + "\n"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_title(result: ScanResult) -> str:
    scan_date = result.started_at.strftime("%Y-%m-%d")
    return (
        f"# Broken Access Control Assessment Report\n\n"
        f"**Target:** {result.target}  \n"
        f"**Date:** {scan_date}  \n"
        f"**Tool:** BAC Detector v0.1.0  \n"
        f"**Scan ID:** `{result.scan_id}`"
    )


def _render_executive_summary(result: ScanResult) -> str:
    total = len(result.findings)
    confirmed = len([f for f in result.findings if f.confidence == Confidence.CONFIRMED])
    potential = len([f for f in result.findings if f.confidence == Confidence.POTENTIAL])

    counts = result.finding_counts_by_severity
    sev_lines = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            label = _SEVERITY_LABEL[sev]
            sev_lines.append(f"- {label}: **{n}**")

    if total == 0:
        assessment = (
            "No broken access control issues were detected during this scan. "
            "This may indicate that authorization controls are properly implemented, "
            "or that the scan coverage was insufficient. "
            "Review the tested endpoints and identity profiles to assess coverage."
        )
    elif confirmed > 0:
        assessment = (
            f"**{confirmed} confirmed** broken access control issue(s) were identified "
            f"that require immediate attention. "
            + (f"An additional {potential} potential issue(s) require manual verification. " if potential else "")
            + "See individual findings for reproduction steps and remediation guidance."
        )
    else:
        assessment = (
            f"**{potential} potential** broken access control issue(s) were identified "
            f"that require manual verification. "
            "No issues could be automatically confirmed. "
            "Review the potential findings and verify using the provided reproduction steps."
        )

    lines = [
        "## Executive Summary",
        "",
        assessment,
        "",
        "### Finding Counts",
        "",
        "| | |",
        "|---|---|",
        f"| Total findings | {total} |",
        f"| Confirmed | {confirmed} |",
        f"| Potential | {potential} |",
    ]

    if sev_lines:
        lines += ["", "### Severity Breakdown", ""]
        lines += sev_lines

    return "\n".join(lines)


def _render_scan_metadata(result: ScanResult) -> str:
    duration = result.duration_seconds
    duration_str = f"{duration:.1f}s" if duration is not None else "—"

    rows = [
        ("Scan ID", f"`{result.scan_id}`"),
        ("Target", result.target),
        ("Status", result.status.value),
        ("Started", result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Duration", duration_str),
        ("Endpoints discovered", str(result.endpoints_discovered)),
        ("Discovery sources", ", ".join(result.discovery_sources_used) or "—"),
        ("Requests sent", str(result.requests_made)),
        ("Identities tested", ", ".join(f"`{i}`" for i in result.identities_tested)),
    ]

    lines = ["## Scan Metadata", "", "| Property | Value |", "|---|---|"]
    for key, value in rows:
        lines.append(f"| {key} | {value} |")

    if result.warnings:
        lines += ["", "**Warnings:**", ""]
        for w in result.warnings:
            lines.append(f"- {w}")

    return "\n".join(lines)


def _render_auth_matrix(result: ScanResult) -> str:
    if not result.auth_matrix:
        return ""

    identity_names: list[str] = []
    for identity_map in result.auth_matrix.values():
        for name in identity_map:
            if name not in identity_names:
                identity_names.append(name)

    header = "| Endpoint | " + " | ".join(identity_names) + " |"
    separator = "|---|" + "---|" * len(identity_names)

    rows = []
    for ep_key, identity_map in sorted(result.auth_matrix.items()):
        cells = [f"`{ep_key}`"]
        for name in identity_names:
            code = identity_map.get(name, -1)
            if code == -1:
                cells.append("—")
            elif 200 <= code < 300:
                cells.append(f"✅ {code}")
            elif code in (401, 403):
                cells.append(f"🚫 {code}")
            elif code == 0:
                cells.append("❌ err")
            else:
                cells.append(str(code))
        rows.append("| " + " | ".join(cells) + " |")

    lines = [
        "## Authorization Matrix",
        "",
        "_✅ = access granted (2xx)  🚫 = access denied (401/403)  ❌ = error_",
        "",
        header,
        separator,
    ] + rows

    return "\n".join(lines)


def _render_findings_section(
    title: str,
    findings: list[Finding],
    detail_level: str,
) -> str:
    lines = [f"## {title}", ""]

    if detail_level == "summary":
        lines.append(
            "_These findings have a high probability of being false positives. "
            "They are included for completeness but should be manually verified "
            "before inclusion in a final report._"
        )
        lines.append("")

    for i, finding in enumerate(findings, 1):
        if detail_level == "full":
            lines.append(_render_finding_full(finding, index=i))
        else:
            lines.append(_render_finding_summary(finding, index=i))

    return "\n".join(lines)


def _render_finding_full(finding: Finding, index: int) -> str:
    """Render a complete finding section with all fields."""
    sev_label = _SEVERITY_LABEL.get(finding.severity.value, finding.severity.value)
    conf_label = _CONFIDENCE_LABEL.get(finding.confidence.value, finding.confidence.value)

    lines = [
        f"### Finding {index}: {finding.title}",
        "",
        "| | |",
        "|---|---|",
        f"| **Severity** | {sev_label} |",
        f"| **Confidence** | {conf_label} |",
        "| **Category** | " + _CATEGORY_LABEL.get(finding.category, f"`{finding.category}`") + " |",
        f"| **Endpoint** | `{finding.endpoint_key}` |",
        f"| **Method** | `{finding.http_method}` |",
        f"| **Attacker identity** | `{finding.evidence.attacker_identity}` |",
    ]

    if finding.evidence.victim_identity:
        lines.append(f"| **Victim identity** | `{finding.evidence.victim_identity}` |")
    if finding.evidence.object_id:
        lines.append(f"| **Object ID** | `{finding.evidence.object_id}` |")

    lines += [
        "",
        "#### Description",
        "",
        finding.description,
        "",
        "#### Evidence",
        "",
        finding.evidence.diff_summary,
    ]

    if finding.evidence.attacker_body_snippet:
        snippet = finding.evidence.attacker_body_snippet.strip()
        if snippet:
            lines += [
                "",
                "**Response snippet (attacker):**",
                "",
                "```",
                snippet[:512],
                "```",
            ]

    lines += [
        "",
        "#### Reproduction Steps",
        "",
    ]
    for i, step in enumerate(finding.reproduction_steps, 1):
        lines.append(f"{i}. {step}")

    lines += [
        "",
        "#### Why This Is Broken Access Control",
        "",
        finding.why_bac,
        "",
        "#### Business Impact",
        "",
        finding.business_impact,
        "",
        "#### Remediation",
        "",
        finding.remediation,
        "",
    ]

    return "\n".join(lines)


def _render_finding_summary(finding: Finding, index: int) -> str:
    """Render a one-line summary for low-signal findings."""
    sev_label = _SEVERITY_LABEL.get(finding.severity.value, finding.severity.value)
    return (
        f"**{index}. {finding.title}**  \n"
        f"Severity: {sev_label} | Endpoint: `{finding.endpoint_key}` | "
        f"Attacker: `{finding.evidence.attacker_identity}`  \n"
        f"{finding.evidence.diff_summary}\n"
    )


def _render_appendix_endpoints(result: ScanResult) -> str:
    if not result.endpoints:
        return "## Appendix: Tested Endpoints\n\n_No endpoint data available._"

    lines = [
        "## Appendix: Tested Endpoints",
        "",
        f"_{result.endpoints_discovered} endpoints discovered "
        f"from {', '.join(result.discovery_sources_used) or 'unknown source'}._",
        "",
        "| Method | Path | IDOR Candidate |",
        "|---|---|---|",
    ]

    for ep_dict in result.endpoints:
        method = ep_dict.get("method", "?")
        path = ep_dict.get("path", "?")
        params = ep_dict.get("parameters", [])
        has_id = any(p.get("likely_object_id") for p in params)
        idor_flag = "✓" if has_id else ""
        lines.append(f"| `{method}` | `{path}` | {idor_flag} |")

    return "\n".join(lines)
