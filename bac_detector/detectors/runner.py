"""
Detection runner.

Orchestrates all detectors, collects findings, deduplicates across
detector outputs, and returns the final finding list.

This is the single entry point called from the CLI scan command.
"""

from __future__ import annotations

from bac_detector.analyzers.baseline import Baseline
from bac_detector.analyzers.matrix import AuthMatrix
from bac_detector.detectors.escalation import (
    detect_horizontal_escalation,
    detect_vertical_escalation,
)
from bac_detector.detectors.idor import detect_idor
from bac_detector.models.finding import Finding
from bac_detector.models.identity import IdentityProfile
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


def run_detection(
    matrix: AuthMatrix,
    baselines: list[Baseline],
    profiles: list[IdentityProfile],
) -> list[Finding]:
    """
    Run all BAC detectors and return a deduplicated finding list.

    Detectors run in order:
      1. IDOR / BOLA (object-level authorization)
      2. Vertical privilege escalation (function-level authorization)
      3. Horizontal privilege escalation (account-scoped access)

    Findings are deduplicated by (category, endpoint_key, attacker_identity,
    object_id) to prevent the same issue being reported by multiple detectors.

    Args:
        matrix: The populated authorization matrix from Phase 3.
        baselines: Owner baselines built from the matrix.
        profiles: All configured identity profiles.

    Returns:
        Deduplicated list of Finding objects, sorted by severity then endpoint.
    """
    log.info(
        "detection_starting",
        endpoints=len(matrix.endpoint_keys),
        baselines=len(baselines),
        identities=[p.name for p in profiles],
    )

    all_findings: list[Finding] = []

    # --- IDOR / BOLA ---
    idor_findings = detect_idor(matrix, baselines, profiles)
    log.info("idor_detection_complete", count=len(idor_findings))
    all_findings.extend(idor_findings)

    # --- Vertical escalation ---
    vertical_findings = detect_vertical_escalation(matrix, profiles)
    log.info("vertical_detection_complete", count=len(vertical_findings))
    all_findings.extend(vertical_findings)

    # --- Horizontal escalation ---
    horizontal_findings = detect_horizontal_escalation(matrix, profiles)
    log.info("horizontal_detection_complete", count=len(horizontal_findings))
    all_findings.extend(horizontal_findings)

    # Deduplicate and sort
    findings = _deduplicate(all_findings)
    findings = _sort_findings(findings)

    log.info(
        "detection_complete",
        total=len(findings),
        idor=len(idor_findings),
        vertical=len(vertical_findings),
        horizontal=len(horizontal_findings),
        after_dedup=len(findings),
    )

    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings across detectors.

    Deduplication key: (category, endpoint_key, attacker_identity, object_id).
    When duplicates exist, the one with higher confidence is kept.
    """
    _CONFIDENCE_RANK = {"confirmed": 0, "potential": 1, "fp_risk": 2}

    best: dict[tuple[str, str, str, str | None], Finding] = {}
    for finding in findings:
        key = (
            finding.category,
            finding.endpoint_key,
            finding.evidence.attacker_identity,
            finding.evidence.object_id,
        )
        existing = best.get(key)
        if existing is None:
            best[key] = finding
        else:
            # Keep whichever has higher confidence (lower rank number)
            existing_rank = _CONFIDENCE_RANK.get(existing.confidence.value, 99)
            new_rank = _CONFIDENCE_RANK.get(finding.confidence.value, 99)
            if new_rank < existing_rank:
                best[key] = finding

    return list(best.values())


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings: severity (critical first) then confidence then endpoint.
    """
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    _CONFIDENCE_ORDER = {"confirmed": 0, "potential": 1, "fp_risk": 2}

    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity.value, 99),
            _CONFIDENCE_ORDER.get(f.confidence.value, 99),
            f.endpoint_key,
        ),
    )
