"""
Authorization Graph Engine — service (G3 orchestration).

run_graph_analysis() is the single entry point for the graph analysis phase.
It receives an already-built and inferred AuthGraph plus a GraphAnalysisConfig,
runs all enabled analyzers, deduplicates and sorts the findings, and returns
them as a flat list of Finding objects that merge cleanly with the existing
detection pipeline output.

The service owns:
- which analyzers run (controlled by GraphAnalysisConfig flags)
- deduplication (same category + endpoint dedup across analyzers)
- severity-then-confidence sort order (consistent with detectors.runner)
- logging of per-analyzer and total counts
"""

from __future__ import annotations

from bac_detector.config.loader import GraphAnalysisConfig
from bac_detector.graph.analyzers import (
    analyze_child_resource_exposure,
    analyze_hidden_privilege_path,
    analyze_inconsistent_sibling_actions,
    analyze_ownership_inconsistency,
    analyze_partial_authorization,
    analyze_tenant_boundary_inconsistency,
)
from bac_detector.graph.models import AuthGraph
from bac_detector.models.finding import Confidence, Finding, Severity
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)

# Sort order for severity (lower index = shown first)
_SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value:     1,
    Severity.MEDIUM.value:   2,
    Severity.LOW.value:      3,
    Severity.INFO.value:     4,
}

_CONFIDENCE_ORDER: dict[str, int] = {
    Confidence.CONFIRMED.value: 0,
    Confidence.POTENTIAL.value: 1,
    Confidence.FP_RISK.value:   2,
}

_MIN_CONFIDENCE_RANK: dict[str, int] = {
    "high":   0,   # only HIGH-severity or above
    "medium": 1,   # MEDIUM and above
    "low":    2,   # everything
}


def run_graph_analysis(
    graph: AuthGraph,
    config: GraphAnalysisConfig,
) -> list[Finding]:
    """
    Run all enabled graph analyzers and return a merged, deduplicated finding list.

    Analyzers are run only when their corresponding config flag is True.
    The min_confidence filter is applied after all analyzers complete, so
    that deduplication sees the full set before any are dropped.

    Args:
        graph: Fully built and inferred AuthGraph (output of build_graph).
        config: Graph analysis configuration controlling which analyzers run.

    Returns:
        Deduplicated, sorted list of Finding objects ready to merge with
        the main detection pipeline output.
    """
    if not config.enabled:
        return []

    all_findings: list[Finding] = []

    # Analyzer 1: inconsistent sibling action protection
    # Always enabled when graph analysis is on — core structural check
    raw = analyze_inconsistent_sibling_actions(graph)
    all_findings.extend(raw)
    log.debug("graph_service_sibling", count=len(raw))

    # Analyzer 2: child-resource exposure
    raw = analyze_child_resource_exposure(graph)
    all_findings.extend(raw)
    log.debug("graph_service_child_exposure", count=len(raw))

    # Analyzer 3: hidden privilege path
    if config.enable_hidden_privilege_path_checks:
        raw = analyze_hidden_privilege_path(graph)
        all_findings.extend(raw)
        log.debug("graph_service_hidden_privilege", count=len(raw))

    # Analyzer 4: tenant boundary inconsistency
    if config.infer_tenant_boundaries:
        raw = analyze_tenant_boundary_inconsistency(graph)
        all_findings.extend(raw)
        log.debug("graph_service_tenant_boundary", count=len(raw))

    # Analyzer 5: ownership inconsistency (requires ownership inference)
    if config.infer_ownership:
        raw = analyze_ownership_inconsistency(graph)
        all_findings.extend(raw)
        log.debug("graph_service_ownership", count=len(raw))

    # Analyzer 6: partial authorization enforcement
    raw = analyze_partial_authorization(graph)
    all_findings.extend(raw)
    log.debug("graph_service_partial_auth", count=len(raw))

    # Deduplicate: same (category, endpoint_key, attacker_identity) tuple
    deduped = _deduplicate(all_findings)

    # Apply minimum confidence filter
    min_rank = _MIN_CONFIDENCE_RANK.get(config.min_confidence, 2)
    filtered = [
        f for f in deduped
        if _CONFIDENCE_ORDER.get(f.confidence.value, 99) <= min_rank
    ]

    # Sort: critical first, confirmed before potential
    sorted_findings = sorted(
        filtered,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity.value, 99),
            _CONFIDENCE_ORDER.get(f.confidence.value, 99),
        ),
    )

    log.info(
        "graph_analysis_complete",
        raw=len(all_findings),
        after_dedup=len(deduped),
        after_filter=len(sorted_findings),
        min_confidence=config.min_confidence,
    )

    return sorted_findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings based on (category, endpoint_key, attacker_identity).

    When duplicates exist, keep the one with the highest confidence.
    """
    # key → (finding, confidence_rank)
    best: dict[tuple[str, str, str], tuple[Finding, int]] = {}

    for f in findings:
        key = (f.category, f.endpoint_key, f.evidence.attacker_identity)
        rank = _CONFIDENCE_ORDER.get(f.confidence.value, 99)
        existing = best.get(key)
        if existing is None or rank < existing[1]:
            best[key] = (f, rank)

    return [f for f, _ in best.values()]
