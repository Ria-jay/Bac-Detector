"""
Unit tests for core data models.

Tests cover construction, validation, computed properties,
and edge cases for all Phase 1 models.
"""

import pytest
from pydantic import ValidationError

from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
from bac_detector.models.finding import Confidence, Evidence, Finding, Severity
from bac_detector.models.identity import AuthMechanism, IdentityProfile
from bac_detector.models.response_meta import ResponseMeta, _extract_json_keys, _hash_body
from bac_detector.models.scan_result import ScanResult, ScanStatus

# ---------------------------------------------------------------------------
# Endpoint model
# ---------------------------------------------------------------------------


class TestEndpoint:
    def test_basic_construction(self):
        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/users/{user_id}",
            base_url="https://api.example.com",
            source="openapi",
        )
        assert ep.method == HttpMethod.GET
        assert ep.path == "/api/users/{user_id}"

    def test_path_auto_slash(self):
        ep = Endpoint(
            method=HttpMethod.GET,
            path="api/users",
            base_url="https://api.example.com",
            source="endpoint_list",
        )
        assert ep.path.startswith("/")

    def test_full_url(self):
        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/users/1",
            base_url="https://api.example.com",
            source="openapi",
        )
        assert ep.full_url == "https://api.example.com/api/users/1"

    def test_endpoint_key(self):
        ep = Endpoint(
            method=HttpMethod.DELETE,
            path="/api/orders/{id}",
            base_url="https://api.example.com",
            source="openapi",
        )
        assert ep.endpoint_key == "DELETE /api/orders/{id}"

    def test_object_id_params_filter(self):
        params = [
            Parameter(name="user_id", location=ParameterLocation.PATH, likely_object_id=True),
            Parameter(name="format", location=ParameterLocation.QUERY, likely_object_id=False),
        ]
        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/users/{user_id}",
            base_url="https://api.example.com",
            source="openapi",
            parameters=params,
        )
        assert len(ep.object_id_params) == 1
        assert ep.object_id_params[0].name == "user_id"

    def test_invalid_source_rejected(self):
        with pytest.raises(ValidationError):
            Endpoint(
                method=HttpMethod.GET,
                path="/api/test",
                base_url="https://api.example.com",
                source="invalid_source",  # not in Literal
            )


# ---------------------------------------------------------------------------
# Parameter model
# ---------------------------------------------------------------------------


class TestParameter:
    def test_object_id_flag(self):
        p = Parameter(
            name="order_id",
            location=ParameterLocation.PATH,
            likely_object_id=True,
        )
        assert p.likely_object_id is True

    def test_defaults(self):
        p = Parameter(name="page", location=ParameterLocation.QUERY)
        assert p.likely_object_id is False
        assert p.example_value is None
        assert p.required is False


# ---------------------------------------------------------------------------
# IdentityProfile model
# ---------------------------------------------------------------------------


class TestIdentityProfile:
    """
    Tests for IdentityProfile model-level concerns only.
    Auth header/cookie construction is tested in test_auth.py.
    """

    def test_blank_name_rejected(self):
        with pytest.raises(ValidationError):
            IdentityProfile(
                name="   ",
                role="user",
                auth_mechanism=AuthMechanism.BEARER,
                token="tok",
            )

    def test_blank_role_rejected(self):
        with pytest.raises(ValidationError):
            IdentityProfile(
                name="alice",
                role="",
                auth_mechanism=AuthMechanism.BEARER,
                token="tok",
            )

    def test_name_stripped_of_whitespace(self):
        identity = IdentityProfile(
            name="  alice  ",
            role="user",
            auth_mechanism=AuthMechanism.NONE,
        )
        assert identity.name == "alice"

    def test_owned_object_ids_default_empty(self):
        identity = IdentityProfile(
            name="alice",
            role="user",
            auth_mechanism=AuthMechanism.NONE,
        )
        assert identity.owned_object_ids == []

    def test_custom_headers_default_empty(self):
        identity = IdentityProfile(
            name="alice",
            role="user",
            auth_mechanism=AuthMechanism.NONE,
        )
        assert identity.custom_headers == {}

    def test_frozen_model_immutable(self):
        identity = IdentityProfile(
            name="alice",
            role="user",
            auth_mechanism=AuthMechanism.NONE,
        )
        with pytest.raises((ValueError, TypeError)):
            identity.name = "bob"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ResponseMeta model
# ---------------------------------------------------------------------------


class TestResponseMeta:
    def test_from_response_factory(self):
        meta = ResponseMeta.from_response(
            status_code=200,
            body='{"id": 1, "name": "Alice"}',
            content_type="application/json",
            latency_ms=42.5,
            endpoint_key="GET /api/users/{id}",
            identity_name="alice",
            requested_url="https://api.example.com/api/users/1",
            object_id_used="1",
        )
        assert meta.status_code == 200
        assert meta.is_success is True
        assert meta.is_access_denied is False
        assert "id" in meta.json_keys
        assert "name" in meta.json_keys
        assert meta.object_id_used == "1"
        assert len(meta.body_hash) == 16

    def test_access_denied_flags(self):
        for code in (401, 403):
            meta = ResponseMeta.from_response(
                status_code=code,
                body="Forbidden",
                content_type="text/plain",
                latency_ms=10.0,
                endpoint_key="GET /api/admin",
                identity_name="guest",
                requested_url="https://api.example.com/api/admin",
            )
            assert meta.is_access_denied is True
            assert meta.is_success is False

    def test_non_json_body_empty_keys(self):
        meta = ResponseMeta.from_response(
            status_code=200,
            body="<html>hello</html>",
            content_type="text/html",
            latency_ms=5.0,
            endpoint_key="GET /",
            identity_name="alice",
            requested_url="https://example.com/",
        )
        assert meta.json_keys == []

    def test_body_snippet_truncated(self):
        long_body = "x" * 1000
        meta = ResponseMeta.from_response(
            status_code=200,
            body=long_body,
            content_type="text/plain",
            latency_ms=1.0,
            endpoint_key="GET /",
            identity_name="alice",
            requested_url="https://example.com/",
        )
        assert len(meta.body_snippet) == 256


class TestResponseMetaHelpers:
    def test_hash_body_deterministic(self):
        h1 = _hash_body("hello world")
        h2 = _hash_body("hello world")
        assert h1 == h2
        assert len(h1) == 16

    def test_hash_body_different_inputs(self):
        assert _hash_body("a") != _hash_body("b")

    def test_extract_json_keys_valid(self):
        keys = _extract_json_keys('{"z": 1, "a": 2}')
        assert keys == ["a", "z"]  # sorted

    def test_extract_json_keys_array(self):
        # JSON arrays don't have top-level keys
        assert _extract_json_keys("[1, 2, 3]") == []

    def test_extract_json_keys_invalid(self):
        assert _extract_json_keys("not json") == []


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class TestFinding:
    def _make_evidence(self) -> Evidence:
        return Evidence(
            attacker_identity="guest",
            victim_identity="alice",
            object_id="42",
            attacker_status_code=200,
            victim_status_code=200,
            attacker_body_snippet='{"id": 42, "email": "alice@example.com"}',
            attacker_body_hash="abc123",
            diff_summary="Guest received Alice's profile data.",
            requested_url="https://api.example.com/api/users/42",
        )

    def test_finding_construction(self):
        finding = Finding(
            title="IDOR on /api/users/{id}",
            category="IDOR",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            endpoint_key="GET /api/users/{id}",
            endpoint_url="https://api.example.com/api/users/{id}",
            http_method="GET",
            evidence=self._make_evidence(),
            description="Guest user accessed Alice's profile.",
            reproduction_steps=[
                "Authenticate as guest",
                "Send GET /api/users/42",
                "Observe Alice's data in response",
            ],
            why_bac="No ownership check is performed on the user_id parameter.",
            business_impact="Any user can access any other user's profile data.",
            remediation="Verify the authenticated user owns the requested resource before returning data.",
        )
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.id is not None  # auto-generated UUID

    def test_finding_id_is_unique(self):
        evidence = self._make_evidence()
        kwargs = dict(
            title="Test",
            category="IDOR",
            severity=Severity.LOW,
            confidence=Confidence.POTENTIAL,
            endpoint_key="GET /api/test",
            endpoint_url="https://example.com/api/test",
            http_method="GET",
            evidence=evidence,
            description="Test",
            why_bac="Test",
            business_impact="Test",
            remediation="Test",
        )
        f1 = Finding(**kwargs)
        f2 = Finding(**kwargs)
        assert f1.id != f2.id


# ---------------------------------------------------------------------------
# ScanResult model
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(
            scan_id="test-123",
            target="https://api.example.com",
        )
        assert result.status == ScanStatus.PENDING
        assert result.findings == []
        assert result.duration_seconds is None

    def test_duration_computed(self):
        from datetime import datetime, timedelta

        start = datetime(2024, 1, 1, 12, 0, 0)
        end = start + timedelta(seconds=42)
        result = ScanResult(
            scan_id="test-456",
            target="https://api.example.com",
            started_at=start,
            finished_at=end,
        )
        assert result.duration_seconds == pytest.approx(42.0)

    def test_finding_counts_by_severity(self):
        from bac_detector.models.finding import Evidence

        evidence = Evidence(
            attacker_identity="guest",
            attacker_status_code=200,
            attacker_body_hash="abc",
            diff_summary="test",
            requested_url="https://example.com/",
        )
        finding_kwargs = dict(
            title="Test",
            category="IDOR",
            confidence=Confidence.POTENTIAL,
            endpoint_key="GET /test",
            endpoint_url="https://example.com/test",
            http_method="GET",
            evidence=evidence,
            description="x",
            why_bac="x",
            business_impact="x",
            remediation="x",
        )
        result = ScanResult(
            scan_id="test-789",
            target="https://example.com",
            findings=[
                Finding(severity=Severity.HIGH, **finding_kwargs),
                Finding(severity=Severity.HIGH, **finding_kwargs),
                Finding(severity=Severity.MEDIUM, **finding_kwargs),
            ],
        )
        counts = result.finding_counts_by_severity
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts.get("low", 0) == 0
