"""
Unit tests for analyzers/matrix.py and analyzers/baseline.py.

Tests cover matrix recording, querying, status summary, baseline
extraction from ownership, and edge cases.
"""

from datetime import datetime

import pytest

from bac_detector.analyzers.baseline import Baseline, build_baselines
from bac_detector.analyzers.matrix import AuthMatrix, build_matrix
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
    body: str = '{"id": 1}',
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


def _identity(
    name: str,
    owned_ids: list[str] | None = None,
) -> IdentityProfile:
    return IdentityProfile(
        name=name,
        role="user",
        auth_mechanism=AuthMechanism.NONE,
        owned_object_ids=owned_ids or [],
    )


# ---------------------------------------------------------------------------
# AuthMatrix
# ---------------------------------------------------------------------------


class TestAuthMatrix:
    def test_record_and_retrieve(self):
        m = AuthMatrix()
        meta = _meta()
        m.record(meta)
        result = m.get("GET /api/users/{id}", "alice", "1")
        assert result is not None
        assert result.status_code == 200

    def test_missing_cell_returns_none(self):
        m = AuthMatrix()
        assert m.get("GET /api/orders", "alice") is None

    def test_endpoint_keys_populated(self):
        m = AuthMatrix()
        m.record(_meta("GET /api/users/{id}", "alice"))
        m.record(_meta("GET /api/orders", "alice", object_id=None))
        assert "GET /api/users/{id}" in m.endpoint_keys
        assert "GET /api/orders" in m.endpoint_keys

    def test_identities_for_endpoint(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice"))
        m.record(_meta(identity="bob"))
        identities = m.identities_for("GET /api/users/{id}")
        assert set(identities) == {"alice", "bob"}

    def test_all_responses_for_endpoint(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", object_id="1"))
        m.record(_meta(identity="bob", object_id="1"))
        responses = m.all_responses_for_endpoint("GET /api/users/{id}")
        assert len(responses) == 2

    def test_responses_for_identity(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", object_id="1"))
        m.record(_meta(identity="alice", object_id="2"))
        m.record(_meta(identity="bob", object_id="1"))
        alice_responses = m.responses_for_identity("GET /api/users/{id}", "alice")
        assert len(alice_responses) == 2

    def test_total_cells(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", object_id="1"))
        m.record(_meta(identity="alice", object_id="2"))
        m.record(_meta(identity="bob", object_id="1"))
        assert m.total_cells == 3

    def test_overwrite_same_cell(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", object_id="1", status=200))
        m.record(_meta(identity="alice", object_id="1", status=403))
        # Second write overwrites
        result = m.get("GET /api/users/{id}", "alice", "1")
        assert result.status_code == 403
        assert m.total_cells == 1

    def test_to_status_summary(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", status=200, object_id="1"))
        m.record(_meta(identity="bob", status=403, object_id="1"))
        summary = m.to_status_summary()
        assert summary["GET /api/users/{id}"]["alice"] == 200
        assert summary["GET /api/users/{id}"]["bob"] == 403

    def test_status_summary_picks_nonzero_status(self):
        m = AuthMatrix()
        # Error response (status=0) then success — summary should show 0 if only error exists
        error_meta = ResponseMeta(
            status_code=0,
            body_hash="error",
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
        m.record(error_meta)
        summary = m.to_status_summary()
        assert summary["GET /api/users/{id}"]["alice"] == 0


class TestBuildMatrix:
    def test_build_from_responses(self):
        responses = [
            _meta(identity="alice", status=200, object_id="1"),
            _meta(identity="bob", status=403, object_id="1"),
        ]
        m = build_matrix(responses)
        assert m.total_cells == 2
        assert m.get("GET /api/users/{id}", "alice", "1").status_code == 200
        assert m.get("GET /api/users/{id}", "bob", "1").status_code == 403

    def test_build_from_empty_list(self):
        m = build_matrix([])
        assert m.total_cells == 0
        assert m.endpoint_keys == []


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class TestBuildBaselines:
    def test_owner_baseline_captured(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", status=200, object_id="1"))
        m.record(_meta(identity="bob", status=403, object_id="1"))
        profiles = [
            _identity("alice", owned_ids=["1"]),
            _identity("bob"),
        ]
        baselines = build_baselines(m, profiles)
        assert len(baselines) == 1
        assert baselines[0].owner_identity == "alice"
        assert baselines[0].object_id == "1"
        assert baselines[0].response.status_code == 200

    def test_non_owner_response_not_baseline(self):
        m = AuthMatrix()
        # bob gets 200 for object_id=1, but alice owns 1
        m.record(_meta(identity="alice", status=200, object_id="1"))
        m.record(_meta(identity="bob", status=200, object_id="1"))
        profiles = [
            _identity("alice", owned_ids=["1"]),
            _identity("bob"),
        ]
        baselines = build_baselines(m, profiles)
        # Only alice's response is a baseline (she's the owner)
        assert all(b.owner_identity == "alice" for b in baselines)

    def test_failed_owner_response_excluded(self):
        m = AuthMatrix()
        # Owner gets 500 — not a valid baseline
        m.record(_meta(identity="alice", status=500, object_id="1"))
        profiles = [_identity("alice", owned_ids=["1"])]
        baselines = build_baselines(m, profiles)
        assert baselines == []

    def test_no_object_id_no_baseline(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", status=200, object_id=None))
        profiles = [_identity("alice", owned_ids=["1"])]
        baselines = build_baselines(m, profiles)
        assert baselines == []

    def test_multiple_endpoints_multiple_baselines(self):
        m = AuthMatrix()
        m.record(_meta("GET /api/users/{id}", "alice", 200, object_id="1"))
        m.record(_meta("GET /api/orders/{id}", "alice", 200, object_id="101"))
        profiles = [_identity("alice", owned_ids=["1", "101"])]
        baselines = build_baselines(m, profiles)
        assert len(baselines) == 2
        ep_keys = {b.endpoint_key for b in baselines}
        assert "GET /api/users/{id}" in ep_keys
        assert "GET /api/orders/{id}" in ep_keys

    def test_baseline_fields_correct(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", status=200, object_id="42"))
        profiles = [_identity("alice", owned_ids=["42"])]
        baselines = build_baselines(m, profiles)
        b = baselines[0]
        assert b.endpoint_key == "GET /api/users/{id}"
        assert b.object_id == "42"
        assert b.owner_identity == "alice"
        assert isinstance(b.response, ResponseMeta)

    def test_no_owned_ids_no_baselines(self):
        m = AuthMatrix()
        m.record(_meta(identity="alice", status=200, object_id="1"))
        profiles = [_identity("alice", owned_ids=[])]
        baselines = build_baselines(m, profiles)
        assert baselines == []
