"""
Unit tests for comparators/response.py.

Tests cover ResponseDiff construction, suspicious-flag logic,
equivalence detection, and non-determinism heuristic.
"""

import pytest

from bac_detector.comparators.response import (
    ResponseDiff,
    compare_responses,
    is_likely_nondeterministic,
    responses_look_equivalent,
)
from bac_detector.models.response_meta import ResponseMeta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _meta(
    status: int = 200,
    body: str = '{"id": 1, "name": "alice"}',
    identity: str = "alice",
    object_id: str | None = "1",
    endpoint_key: str = "GET /api/users/{id}",
) -> ResponseMeta:
    return ResponseMeta.from_response(
        status_code=status,
        body=body,
        content_type="application/json",
        latency_ms=10.0,
        endpoint_key=endpoint_key,
        identity_name=identity,
        requested_url=f"https://api.example.com/api/users/{object_id or ''}",
        object_id_used=object_id,
    )


# ---------------------------------------------------------------------------
# compare_responses
# ---------------------------------------------------------------------------


class TestCompareResponses:
    def test_identical_responses_no_diff(self):
        body = '{"id": 1, "name": "alice"}'
        a = _meta(status=200, body=body, identity="alice")
        b = _meta(status=200, body=body, identity="alice")
        diff = compare_responses(a, b)
        assert diff.status_differs is False
        assert diff.body_differs is False
        assert diff.bodies_identical is True
        assert diff.length_delta == 0

    def test_status_code_difference_detected(self):
        a = _meta(status=200, identity="alice")
        b = _meta(status=403, identity="bob")
        diff = compare_responses(a, b)
        assert diff.status_differs is True
        assert diff.candidate_status == 200
        assert diff.reference_status == 403

    def test_success_where_reference_denied(self):
        attacker = _meta(status=200, identity="bob")
        owner = _meta(status=403, identity="alice")
        diff = compare_responses(candidate=attacker, reference=owner)
        assert diff.success_where_reference_denied is True

    def test_no_success_where_both_denied(self):
        a = _meta(status=403, identity="bob")
        b = _meta(status=403, identity="alice")
        diff = compare_responses(a, b)
        assert diff.success_where_reference_denied is False

    def test_extra_json_keys_detected(self):
        attacker = _meta(body='{"id": 1, "name": "alice", "ssn": "123"}')
        owner = _meta(body='{"id": 1, "name": "alice"}')
        diff = compare_responses(candidate=attacker, reference=owner)
        assert diff.candidate_has_extra_keys is True
        assert "ssn" in diff.extra_keys

    def test_missing_keys_detected(self):
        attacker = _meta(body='{"id": 1}')
        owner = _meta(body='{"id": 1, "name": "alice", "email": "a@b.com"}')
        diff = compare_responses(candidate=attacker, reference=owner)
        assert diff.candidate_missing_keys is True
        assert "name" in diff.missing_keys
        assert "email" in diff.missing_keys

    def test_body_length_delta(self):
        short = _meta(body='{"id": 1}')
        long = _meta(body='{"id": 1, "name": "alice", "email": "alice@example.com"}')
        diff = compare_responses(candidate=long, reference=short)
        assert diff.length_delta > 0

    def test_is_suspicious_success_where_denied(self):
        attacker = _meta(status=200, identity="bob")
        owner = _meta(status=403, identity="alice")
        diff = compare_responses(attacker, owner)
        assert diff.is_suspicious is True

    def test_is_suspicious_extra_keys(self):
        attacker = _meta(body='{"id": 1, "admin_token": "secret"}')
        owner = _meta(body='{"id": 1}')
        diff = compare_responses(attacker, owner)
        assert diff.is_suspicious is True

    def test_not_suspicious_both_denied(self):
        a = _meta(status=403, identity="alice")
        b = _meta(status=403, identity="bob")
        diff = compare_responses(a, b)
        assert diff.is_suspicious is False

    def test_error_responses_bodies_not_identical(self):
        # status=0 means network error — bodies_identical should be False
        a = ResponseMeta(
            status_code=0,
            body_hash="abc",
            body_length=0,
            body_snippet="",
            content_type=None,
            json_keys=[],
            latency_ms=0.0,
            endpoint_key="GET /api/users/{id}",
            identity_name="alice",
            requested_url="https://api.example.com/api/users/1",
            object_id_used="1",
            error="timeout",
        )
        b = _meta(status=200)
        diff = compare_responses(a, b)
        assert diff.bodies_identical is False


# ---------------------------------------------------------------------------
# responses_look_equivalent
# ---------------------------------------------------------------------------


class TestResponsesLookEquivalent:
    def test_same_body_same_status_equivalent(self):
        body = '{"id": 1}'
        a = _meta(status=200, body=body, identity="alice")
        b = _meta(status=200, body=body, identity="bob")
        assert responses_look_equivalent(a, b) is True

    def test_different_body_not_equivalent(self):
        a = _meta(status=200, body='{"id": 1}', identity="alice")
        b = _meta(status=200, body='{"id": 2}', identity="bob")
        assert responses_look_equivalent(a, b) is False

    def test_different_status_not_equivalent(self):
        body = '{"id": 1}'
        a = _meta(status=200, body=body, identity="alice")
        b = _meta(status=403, body=body, identity="bob")
        assert responses_look_equivalent(a, b) is False

    def test_both_non_success_not_equivalent(self):
        a = _meta(status=403, identity="alice")
        b = _meta(status=403, identity="bob")
        # is_success is False — not equivalent per definition
        assert responses_look_equivalent(a, b) is False


# ---------------------------------------------------------------------------
# is_likely_nondeterministic
# ---------------------------------------------------------------------------


class TestIsLikelyNondeterministic:
    def test_single_response_not_nondeterministic(self):
        assert is_likely_nondeterministic([_meta()]) is False

    def test_empty_list_not_nondeterministic(self):
        assert is_likely_nondeterministic([]) is False

    def test_same_hashes_not_nondeterministic(self):
        body = '{"id": 1, "name": "alice"}'
        responses = [
            _meta(status=200, body=body, identity="alice"),
            _meta(status=200, body=body, identity="bob"),
        ]
        assert is_likely_nondeterministic(responses) is False

    def test_different_hashes_same_keys_flagged(self):
        # Same JSON key structure but different values — looks non-deterministic
        responses = [
            _meta(status=200, body='{"id": 1, "ts": "2024-01-01"}', identity="a"),
            _meta(status=200, body='{"id": 1, "ts": "2024-01-02"}', identity="b"),
        ]
        assert is_likely_nondeterministic(responses) is True

    def test_different_keys_not_nondeterministic(self):
        # Different key structure means different resources, not timestamps
        responses = [
            _meta(status=200, body='{"id": 1, "name": "alice"}', identity="a"),
            _meta(status=200, body='{"id": 1, "admin": true}', identity="b"),
        ]
        assert is_likely_nondeterministic(responses) is False
