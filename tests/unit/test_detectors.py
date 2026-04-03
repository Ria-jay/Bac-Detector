"""
Unit tests for the detection engine.

Tests cover IDOR detection, vertical escalation detection,
horizontal escalation detection, confidence scoring, finding
deduplication, and finding sort order.
"""


from bac_detector.analyzers.baseline import Baseline
from bac_detector.analyzers.matrix import AuthMatrix, build_matrix
from bac_detector.comparators.response import compare_responses
from bac_detector.detectors.confidence import (
    score_escalation_confidence,
    score_idor_confidence,
)
from bac_detector.detectors.escalation import (
    detect_horizontal_escalation,
    detect_vertical_escalation,
)
from bac_detector.detectors.idor import detect_idor
from bac_detector.detectors.runner import _deduplicate, _sort_findings, run_detection
from bac_detector.models.finding import Confidence, Finding, Severity
from bac_detector.models.identity import AuthMechanism, IdentityProfile
from bac_detector.models.response_meta import ResponseMeta

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _meta(
    endpoint_key: str = "GET /api/users/{id}",
    identity: str = "alice",
    status: int = 200,
    object_id: str | None = "1",
    body: str = '{"id": 1, "name": "alice"}',
) -> ResponseMeta:
    return ResponseMeta.from_response(
        status_code=status,
        body=body,
        content_type="application/json",
        latency_ms=10.0,
        endpoint_key=endpoint_key,
        identity_name=identity,
        requested_url=f"https://api.example.com{endpoint_key.split(' ', 1)[-1].replace('{id}', object_id or '')}",
        object_id_used=object_id,
    )


def _profile(
    name: str,
    role: str = "user",
    owned_ids: list[str] | None = None,
) -> IdentityProfile:
    return IdentityProfile(
        name=name,
        role=role,
        auth_mechanism=AuthMechanism.NONE,
        owned_object_ids=owned_ids or [],
    )


def _matrix_from(*metas: ResponseMeta) -> AuthMatrix:
    return build_matrix(list(metas))


def _baseline(
    endpoint_key: str,
    object_id: str,
    owner: str,
    status: int = 200,
    body: str = '{"id": 1}',
) -> Baseline:
    return Baseline(
        endpoint_key=endpoint_key,
        object_id=object_id,
        owner_identity=owner,
        response=_meta(endpoint_key=endpoint_key, identity=owner, status=status,
                       object_id=object_id, body=body),
    )


# ---------------------------------------------------------------------------
# Confidence scoring — IDOR
# ---------------------------------------------------------------------------


class TestIdorConfidence:
    def test_confirmed_when_ownership_and_identical_bodies(self):
        owner = _meta(identity="alice", status=200, body='{"id": 1}')
        attacker = _meta(identity="bob", status=200, body='{"id": 1}')
        diff = compare_responses(attacker, owner)
        conf = score_idor_confidence(
            attacker_meta=attacker,
            owner_meta=owner,
            diff=diff,
        )
        assert conf == Confidence.CONFIRMED

    def test_confirmed_when_same_json_keys(self):
        owner = _meta(identity="alice", status=200, body='{"id": 1, "name": "alice"}')
        attacker = _meta(identity="bob", status=200, body='{"id": 1, "name": "alice"}')
        diff = compare_responses(attacker, owner)
        conf = score_idor_confidence(
            attacker_meta=attacker,
            owner_meta=owner,
            diff=diff,
        )
        assert conf == Confidence.CONFIRMED

    def test_potential_when_no_owner_baseline(self):
        attacker = _meta(identity="bob", status=200)
        diff = compare_responses(attacker, attacker)
        conf = score_idor_confidence(
            attacker_meta=attacker,
            owner_meta=None,
            diff=diff,
        )
        assert conf == Confidence.POTENTIAL

    def test_fp_risk_when_attacker_gets_error(self):
        attacker = _meta(identity="bob", status=403)
        owner = _meta(identity="alice", status=200)
        diff = compare_responses(attacker, owner)
        conf = score_idor_confidence(
            attacker_meta=attacker,
            owner_meta=owner,
            diff=diff,
        )
        assert conf == Confidence.FP_RISK

    def test_potential_when_bodies_differ_and_no_key_match(self):
        # Bodies differ and no key overlap — still POTENTIAL (attacker got real content)
        owner = _meta(identity="alice", status=200, body='{"id": 1, "name": "alice"}')
        attacker = _meta(identity="bob", status=200, body='{"id": 1, "email": "x@y.com"}')
        diff = compare_responses(attacker, owner)
        conf = score_idor_confidence(
            attacker_meta=attacker,
            owner_meta=owner,
            diff=diff,
        )
        assert conf == Confidence.POTENTIAL


# ---------------------------------------------------------------------------
# Confidence scoring — Escalation
# ---------------------------------------------------------------------------


class TestEscalationConfidence:
    def test_confirmed_admin_endpoint_with_higher_baseline(self):
        lower = _meta(identity="user", status=200)
        higher = _meta(identity="admin", status=200)
        diff = compare_responses(lower, higher)
        conf = score_escalation_confidence(
            lower_meta=lower,
            higher_meta=higher,
            diff=diff,
            is_admin_endpoint=True,
        )
        assert conf == Confidence.CONFIRMED

    def test_fp_risk_when_lower_denied(self):
        lower = _meta(identity="user", status=403)
        higher = _meta(identity="admin", status=200)
        diff = compare_responses(lower, higher)
        conf = score_escalation_confidence(
            lower_meta=lower,
            higher_meta=higher,
            diff=diff,
            is_admin_endpoint=True,
        )
        assert conf == Confidence.FP_RISK

    def test_fp_risk_when_both_get_identical_responses(self):
        body = '{"public": true}'
        lower = _meta(identity="user", status=200, body=body)
        higher = _meta(identity="admin", status=200, body=body)
        diff = compare_responses(lower, higher)
        conf = score_escalation_confidence(
            lower_meta=lower,
            higher_meta=higher,
            diff=diff,
            is_admin_endpoint=False,
        )
        assert conf == Confidence.FP_RISK

    def test_potential_when_no_higher_but_admin_endpoint(self):
        lower = _meta(identity="user", status=200)
        diff = compare_responses(lower, lower)
        conf = score_escalation_confidence(
            lower_meta=lower,
            higher_meta=None,
            diff=diff,
            is_admin_endpoint=True,
        )
        assert conf == Confidence.POTENTIAL


# ---------------------------------------------------------------------------
# IDOR detector
# ---------------------------------------------------------------------------


class TestDetectIdor:
    def test_confirmed_idor_detected(self):
        # bob (non-owner) accesses alice's object (id=1)
        alice_meta = _meta(identity="alice", status=200, object_id="1")
        bob_meta = _meta(identity="bob", status=200, object_id="1")
        matrix = _matrix_from(alice_meta, bob_meta)
        baselines = [_baseline("GET /api/users/{id}", "1", "alice")]
        profiles = [
            _profile("alice", owned_ids=["1"]),
            _profile("bob"),
        ]
        findings = detect_idor(matrix, baselines, profiles)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "IDOR"
        assert f.evidence.attacker_identity == "bob"
        assert f.evidence.victim_identity == "alice"
        assert f.evidence.object_id == "1"
        assert f.confidence in (Confidence.CONFIRMED, Confidence.POTENTIAL)

    def test_owner_accessing_own_object_not_flagged(self):
        alice_meta = _meta(identity="alice", status=200, object_id="1")
        matrix = _matrix_from(alice_meta)
        baselines = [_baseline("GET /api/users/{id}", "1", "alice")]
        profiles = [_profile("alice", owned_ids=["1"])]
        findings = detect_idor(matrix, baselines, profiles)
        assert findings == []

    def test_denied_non_owner_not_flagged(self):
        alice_meta = _meta(identity="alice", status=200, object_id="1")
        bob_meta = _meta(identity="bob", status=403, object_id="1")
        matrix = _matrix_from(alice_meta, bob_meta)
        baselines = [_baseline("GET /api/users/{id}", "1", "alice")]
        profiles = [
            _profile("alice", owned_ids=["1"]),
            _profile("bob"),
        ]
        findings = detect_idor(matrix, baselines, profiles)
        assert findings == []

    def test_unknown_ownership_not_flagged(self):
        # No profile claims ownership of object_id="99"
        meta = _meta(identity="bob", status=200, object_id="99")
        matrix = _matrix_from(meta)
        profiles = [_profile("alice"), _profile("bob")]
        findings = detect_idor(matrix, [], profiles)
        assert findings == []

    def test_no_object_id_not_flagged(self):
        meta = _meta(identity="bob", status=200, object_id=None,
                     endpoint_key="GET /api/users")
        matrix = _matrix_from(meta)
        profiles = [_profile("alice", owned_ids=["1"]), _profile("bob")]
        findings = detect_idor(matrix, [], profiles)
        assert findings == []

    def test_multiple_non_owners_each_get_finding(self):
        alice_meta = _meta(identity="alice", status=200, object_id="1")
        bob_meta = _meta(identity="bob", status=200, object_id="1")
        carol_meta = _meta(identity="carol", status=200, object_id="1")
        matrix = _matrix_from(alice_meta, bob_meta, carol_meta)
        baselines = [_baseline("GET /api/users/{id}", "1", "alice")]
        profiles = [
            _profile("alice", owned_ids=["1"]),
            _profile("bob"),
            _profile("carol"),
        ]
        findings = detect_idor(matrix, baselines, profiles)
        attackers = {f.evidence.attacker_identity for f in findings}
        assert "bob" in attackers
        assert "carol" in attackers
        assert "alice" not in attackers

    def test_finding_has_required_fields(self):
        alice_meta = _meta(identity="alice", status=200, object_id="1")
        bob_meta = _meta(identity="bob", status=200, object_id="1")
        matrix = _matrix_from(alice_meta, bob_meta)
        baselines = [_baseline("GET /api/users/{id}", "1", "alice")]
        profiles = [_profile("alice", owned_ids=["1"]), _profile("bob")]
        findings = detect_idor(matrix, baselines, profiles)
        assert len(findings) == 1
        f = findings[0]
        assert f.title
        assert f.description
        assert f.why_bac
        assert f.business_impact
        assert f.remediation
        assert f.reproduction_steps
        assert f.http_method == "GET"


# ---------------------------------------------------------------------------
# Vertical escalation detector
# ---------------------------------------------------------------------------


class TestDetectVerticalEscalation:
    def test_user_accessing_admin_endpoint_flagged(self):
        admin_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="admin",
            status=200,
            object_id=None,
        )
        user_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="user",
            status=200,
            object_id=None,
        )
        matrix = _matrix_from(admin_meta, user_meta)
        profiles = [
            _profile("admin", role="admin"),
            _profile("user", role="user"),
        ]
        findings = detect_vertical_escalation(matrix, profiles)
        assert len(findings) >= 1
        attacker_names = {f.evidence.attacker_identity for f in findings}
        assert "user" in attacker_names

    def test_non_admin_endpoint_not_flagged(self):
        user_meta = _meta(
            endpoint_key="GET /api/users",
            identity="user",
            status=200,
            object_id=None,
        )
        matrix = _matrix_from(user_meta)
        profiles = [_profile("user", role="user"), _profile("admin", role="admin")]
        findings = detect_vertical_escalation(matrix, profiles)
        assert findings == []

    def test_user_denied_admin_endpoint_not_flagged(self):
        admin_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="admin",
            status=200,
            object_id=None,
        )
        user_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="user",
            status=403,
            object_id=None,
        )
        matrix = _matrix_from(admin_meta, user_meta)
        profiles = [_profile("admin", role="admin"), _profile("user", role="user")]
        findings = detect_vertical_escalation(matrix, profiles)
        assert findings == []

    def test_vertical_finding_has_required_fields(self):
        admin_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="admin",
            status=200,
            object_id=None,
        )
        user_meta = _meta(
            endpoint_key="GET /api/admin/users",
            identity="user",
            status=200,
            object_id=None,
        )
        matrix = _matrix_from(admin_meta, user_meta)
        profiles = [_profile("admin", role="admin"), _profile("user", role="user")]
        findings = detect_vertical_escalation(matrix, profiles)
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == "vertical_escalation"
        assert f.title
        assert f.remediation


# ---------------------------------------------------------------------------
# Horizontal escalation detector
# ---------------------------------------------------------------------------


class TestDetectHorizontalEscalation:
    def test_same_role_different_bodies_flagged(self):
        alice_meta = _meta(
            endpoint_key="GET /api/me/profile",
            identity="alice",
            status=200,
            object_id=None,
            body='{"id": 1, "name": "alice"}',
        )
        bob_meta = _meta(
            endpoint_key="GET /api/me/profile",
            identity="bob",
            status=200,
            object_id=None,
            body='{"id": 2, "name": "bob"}',
        )
        matrix = _matrix_from(alice_meta, bob_meta)
        profiles = [_profile("alice", role="user"), _profile("bob", role="user")]
        findings = detect_horizontal_escalation(matrix, profiles)
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == "horizontal_escalation"

    def test_same_role_same_body_not_flagged(self):
        body = '{"public": true}'
        alice_meta = _meta(
            endpoint_key="GET /api/me/profile",
            identity="alice",
            status=200,
            object_id=None,
            body=body,
        )
        bob_meta = _meta(
            endpoint_key="GET /api/me/profile",
            identity="bob",
            status=200,
            object_id=None,
            body=body,
        )
        matrix = _matrix_from(alice_meta, bob_meta)
        profiles = [_profile("alice", role="user"), _profile("bob", role="user")]
        findings = detect_horizontal_escalation(matrix, profiles)
        assert findings == []

    def test_non_account_endpoint_not_flagged(self):
        alice_meta = _meta(
            endpoint_key="GET /api/orders",
            identity="alice",
            status=200,
            object_id=None,
            body='{"count": 5}',
        )
        bob_meta = _meta(
            endpoint_key="GET /api/orders",
            identity="bob",
            status=200,
            object_id=None,
            body='{"count": 3}',
        )
        matrix = _matrix_from(alice_meta, bob_meta)
        profiles = [_profile("alice", role="user"), _profile("bob", role="user")]
        # /api/orders doesn't contain account-scoped path signals
        findings = detect_horizontal_escalation(matrix, profiles)
        assert findings == []

    def test_only_one_identity_not_flagged(self):
        meta = _meta(
            endpoint_key="GET /api/me/profile",
            identity="alice",
            status=200,
            object_id=None,
        )
        matrix = _matrix_from(meta)
        profiles = [_profile("alice", role="user")]
        findings = detect_horizontal_escalation(matrix, profiles)
        assert findings == []


# ---------------------------------------------------------------------------
# Detection runner
# ---------------------------------------------------------------------------


class TestRunDetection:
    def test_empty_matrix_produces_no_findings(self):
        matrix = build_matrix([])
        findings = run_detection(matrix, [], [])
        assert findings == []

    def test_findings_sorted_critical_first(self):
        from bac_detector.models.finding import Evidence

        def _finding(sev: Severity, conf: Confidence, ep: str = "GET /api/test") -> Finding:
            evidence = Evidence(
                attacker_identity="bob",
                attacker_status_code=200,
                attacker_body_hash="abc",
                diff_summary="test",
                requested_url="https://example.com",
            )
            return Finding(
                title="Test",
                category="IDOR",
                severity=sev,
                confidence=conf,
                endpoint_key=ep,
                endpoint_url="https://example.com",
                http_method="GET",
                evidence=evidence,
                description="x",
                why_bac="x",
                business_impact="x",
                remediation="x",
            )

        unsorted = [
            _finding(Severity.LOW, Confidence.POTENTIAL),
            _finding(Severity.CRITICAL, Confidence.CONFIRMED),
            _finding(Severity.MEDIUM, Confidence.POTENTIAL),
        ]
        sorted_findings = _sort_findings(unsorted)
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[-1].severity == Severity.LOW

    def test_deduplication_keeps_higher_confidence(self):
        from bac_detector.models.finding import Evidence

        def _finding(conf: Confidence) -> Finding:
            evidence = Evidence(
                attacker_identity="bob",
                object_id="1",
                attacker_status_code=200,
                attacker_body_hash="abc",
                diff_summary="test",
                requested_url="https://example.com",
            )
            return Finding(
                title="Test",
                category="IDOR",
                severity=Severity.HIGH,
                confidence=conf,
                endpoint_key="GET /api/users/{id}",
                endpoint_url="https://example.com",
                http_method="GET",
                evidence=evidence,
                description="x",
                why_bac="x",
                business_impact="x",
                remediation="x",
            )

        potential = _finding(Confidence.POTENTIAL)
        confirmed = _finding(Confidence.CONFIRMED)
        deduped = _deduplicate([potential, confirmed])
        assert len(deduped) == 1
        assert deduped[0].confidence == Confidence.CONFIRMED
