"""
Phase 6 integration tests: end-to-end scan against the demo app.

These tests run the full pipeline — discovery, replay, detection —
against the intentionally-vulnerable demo FastAPI app and assert that:

  1. IDOR is detected: alice accesses bob's user record (and vice versa)
  2. Vertical escalation is detected: alice (user) reaches /admin/users
  3. Horizontal escalation is detected: /me/profile returns distinct data
     per identity (POTENTIAL — correctly flagged for manual review)
  4. Negative control: /health is NOT flagged (it's public and harmless)

Each test is independent and operates on the shared scan result, which
is computed once per session to keep the test suite fast.
"""

from __future__ import annotations

import pytest

from bac_detector.analyzers.baseline import build_baselines
from bac_detector.analyzers.matrix import build_matrix
from bac_detector.config.loader import ScanConfig
from bac_detector.detectors.runner import run_detection
from bac_detector.discovery.runner import run_discovery
from bac_detector.models.finding import Confidence, Finding
from bac_detector.replay.runner import run_replay

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Session-scoped scan result
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def scan_findings(demo_scan_config: ScanConfig) -> list[Finding]:
    """
    Run the full pipeline once and return all findings.

    Shared across all tests in this module — the demo app is hit only once
    per test session.
    """
    # Phase 2: Discovery
    inventory = run_discovery(demo_scan_config)
    assert inventory.total > 0, "Discovery returned no endpoints"

    # Phase 3: Replay
    responses, summary = run_replay(inventory, demo_scan_config)
    assert len(responses) > 0, "Replay returned no responses"

    # Phase 3b: Matrix + baselines
    matrix = build_matrix(responses)
    baselines = build_baselines(matrix, demo_scan_config.identity_profiles)

    # Phase 4: Detection
    findings = run_detection(matrix, baselines, demo_scan_config.identity_profiles)
    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_category(findings: list[Finding], category: str) -> list[Finding]:
    return [f for f in findings if f.category == category]


def _findings_for_endpoint(findings: list[Finding], path_fragment: str) -> list[Finding]:
    return [f for f in findings if path_fragment in f.endpoint_key]


# ---------------------------------------------------------------------------
# Discovery smoke test
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_endpoints_discovered(self, demo_scan_config: ScanConfig):
        inventory = run_discovery(demo_scan_config)
        paths = [ep.path for ep in inventory.endpoints]
        assert any("/users" in p for p in paths), "Expected /users endpoint"
        assert any("/me" in p or "profile" in p for p in paths), "Expected /me/profile"
        assert any("admin" in p for p in paths), "Expected /admin endpoint"

    def test_health_endpoint_discovered(self, demo_scan_config: ScanConfig):
        inventory = run_discovery(demo_scan_config)
        paths = [ep.path for ep in inventory.endpoints]
        assert any("health" in p for p in paths), "Expected /health endpoint"

    def test_user_id_param_flagged_as_idor_candidate(self, demo_scan_config: ScanConfig):
        inventory = run_discovery(demo_scan_config)
        user_endpoints = [
            ep for ep in inventory.endpoints
            if "/users/" in ep.path or "user_id" in ep.path
        ]
        assert any(ep.object_id_params for ep in user_endpoints), (
            "Expected at least one user endpoint to have object_id params flagged"
        )


# ---------------------------------------------------------------------------
# IDOR detection
# ---------------------------------------------------------------------------

class TestIdorDetection:
    def test_idor_finding_exists(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        assert len(idor) >= 1, (
            f"Expected at least 1 IDOR finding, got 0. "
            f"All findings: {[(f.category, f.endpoint_key) for f in scan_findings]}"
        )

    def test_idor_on_users_endpoint(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        on_users = [f for f in idor if "/users" in f.endpoint_key]
        assert len(on_users) >= 1, "Expected IDOR finding on /users/{user_id}"

    def test_idor_attacker_is_non_owner(self, scan_findings: list[Finding]):
        """The attacker identity must not own the accessed object."""
        idor = _findings_by_category(scan_findings, "IDOR")
        for f in idor:
            assert f.evidence.attacker_identity != f.evidence.victim_identity, (
                "Attacker and victim should be different identities"
            )

    def test_idor_has_object_id(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        for f in idor:
            assert f.evidence.object_id is not None, (
                "IDOR findings should have an object_id in evidence"
            )

    def test_idor_confidence_not_fp_risk(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        assert any(f.confidence != Confidence.FP_RISK for f in idor), (
            "Expected at least one IDOR finding with confidence CONFIRMED or POTENTIAL"
        )

    def test_idor_attacker_got_200(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        for f in idor:
            assert f.evidence.attacker_status_code == 200, (
                f"IDOR finding should show attacker got 200, "
                f"got {f.evidence.attacker_status_code}"
            )

    def test_idor_finding_has_reproduction_steps(self, scan_findings: list[Finding]):
        idor = _findings_by_category(scan_findings, "IDOR")
        assert len(idor) >= 1
        assert len(idor[0].reproduction_steps) >= 1


# ---------------------------------------------------------------------------
# Vertical escalation detection
# ---------------------------------------------------------------------------

class TestVerticalEscalation:
    def test_vertical_finding_exists(self, scan_findings: list[Finding]):
        vertical = _findings_by_category(scan_findings, "vertical_escalation")
        assert len(vertical) >= 1, (
            f"Expected at least 1 vertical_escalation finding, got 0. "
            f"All findings: {[(f.category, f.endpoint_key) for f in scan_findings]}"
        )

    def test_vertical_on_admin_endpoint(self, scan_findings: list[Finding]):
        vertical = _findings_by_category(scan_findings, "vertical_escalation")
        on_admin = [f for f in vertical if "admin" in f.endpoint_key]
        assert len(on_admin) >= 1, "Expected vertical escalation finding on /admin/* endpoint"

    def test_vertical_attacker_is_user_role(self, scan_findings: list[Finding]):
        """The attacker must be a low-privilege identity (alice or bob, not admin)."""
        vertical = _findings_by_category(scan_findings, "vertical_escalation")
        for f in vertical:
            assert f.evidence.attacker_identity in ("alice", "bob"), (
                f"Expected attacker to be alice or bob, got {f.evidence.attacker_identity}"
            )

    def test_vertical_confidence_not_fp_risk(self, scan_findings: list[Finding]):
        vertical = _findings_by_category(scan_findings, "vertical_escalation")
        assert any(f.confidence != Confidence.FP_RISK for f in vertical), (
            "Expected at least one vertical finding that is not FP_RISK"
        )

    def test_vertical_has_remediation(self, scan_findings: list[Finding]):
        vertical = _findings_by_category(scan_findings, "vertical_escalation")
        assert len(vertical) >= 1
        assert vertical[0].remediation, "Vertical finding should have remediation text"


# ---------------------------------------------------------------------------
# Horizontal escalation detection
# ---------------------------------------------------------------------------

class TestHorizontalEscalation:
    def test_horizontal_finding_exists(self, scan_findings: list[Finding]):
        horizontal = _findings_by_category(scan_findings, "horizontal_escalation")
        assert len(horizontal) >= 1, (
            f"Expected at least 1 horizontal_escalation finding, got 0. "
            f"All findings: {[(f.category, f.endpoint_key) for f in scan_findings]}"
        )

    def test_horizontal_on_profile_endpoint(self, scan_findings: list[Finding]):
        horizontal = _findings_by_category(scan_findings, "horizontal_escalation")
        on_profile = [f for f in horizontal if "profile" in f.endpoint_key or "me" in f.endpoint_key]
        assert len(on_profile) >= 1, "Expected horizontal finding on /me/profile"

    def test_horizontal_is_potential(self, scan_findings: list[Finding]):
        """Horizontal escalation without object ID swapping can only be POTENTIAL."""
        horizontal = _findings_by_category(scan_findings, "horizontal_escalation")
        for f in horizontal:
            assert f.confidence == Confidence.POTENTIAL, (
                f"Horizontal escalation should be POTENTIAL, got {f.confidence}"
            )

    def test_horizontal_involves_same_role_identities(self, scan_findings: list[Finding]):
        horizontal = _findings_by_category(scan_findings, "horizontal_escalation")
        for f in horizontal:
            # Both alice and bob are users — they should be the pair
            assert f.evidence.attacker_identity in ("alice", "bob")
            assert f.evidence.victim_identity in ("alice", "bob")


# ---------------------------------------------------------------------------
# Negative control: /health must NOT be flagged
# ---------------------------------------------------------------------------

class TestNegativeControl:
    def test_health_endpoint_not_flagged(self, scan_findings: list[Finding]):
        health_findings = _findings_for_endpoint(scan_findings, "health")
        assert len(health_findings) == 0, (
            f"Expected no findings on /health (public endpoint), "
            f"got: {[(f.category, f.confidence.value) for f in health_findings]}"
        )

    def test_no_fp_risk_findings_for_known_bugs(self, scan_findings: list[Finding]):
        """
        The three known bugs should not ALL be downgraded to FP_RISK.
        At least one finding per category should be CONFIRMED or POTENTIAL.
        """
        for category in ("IDOR", "vertical_escalation", "horizontal_escalation"):
            cat_findings = _findings_by_category(scan_findings, category)
            non_fp = [f for f in cat_findings if f.confidence != Confidence.FP_RISK]
            assert len(non_fp) >= 1, (
                f"All {category} findings were downgraded to FP_RISK — "
                f"expected at least one CONFIRMED or POTENTIAL"
            )


# ---------------------------------------------------------------------------
# Finding quality checks
# ---------------------------------------------------------------------------

class TestFindingQuality:
    def test_all_findings_have_titles(self, scan_findings: list[Finding]):
        for f in scan_findings:
            assert f.title, f"Finding {f.id} has no title"

    def test_all_findings_have_description(self, scan_findings: list[Finding]):
        for f in scan_findings:
            assert f.description, f"Finding {f.id} has no description"

    def test_all_findings_have_remediation(self, scan_findings: list[Finding]):
        for f in scan_findings:
            assert f.remediation, f"Finding {f.id} has no remediation"

    def test_all_findings_have_why_bac(self, scan_findings: list[Finding]):
        for f in scan_findings:
            assert f.why_bac, f"Finding {f.id} has no why_bac"

    def test_all_findings_have_valid_severity(self, scan_findings: list[Finding]):
        from bac_detector.models.finding import Severity
        valid = {s.value for s in Severity}
        for f in scan_findings:
            assert f.severity.value in valid
