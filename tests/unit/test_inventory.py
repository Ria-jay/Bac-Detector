"""
Unit tests for the EndpointInventory builder.

Tests cover deduplication, source priority, normalization,
stats properties, and filter methods.
"""

import pytest

from bac_detector.discovery.inventory import EndpointInventory, build_inventory, _deduplicate
from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation

BASE_URL = "https://api.example.com"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_endpoint(
    method: str = "GET",
    path: str = "/api/test",
    source: str = "openapi",
    base_url: str = BASE_URL,
    params: list | None = None,
) -> Endpoint:
    return Endpoint(
        method=HttpMethod(method),
        path=path,
        base_url=base_url,
        parameters=params or [],
        source=source,  # type: ignore[arg-type]
        tags=[],
        summary=None,
    )


def _make_id_param(name: str = "user_id") -> Parameter:
    return Parameter(
        name=name,
        location=ParameterLocation.PATH,
        likely_object_id=True,
        required=True,
    )


# ---------------------------------------------------------------------------
# build_inventory — basic cases
# ---------------------------------------------------------------------------


class TestBuildInventoryBasic:
    def test_empty_batches(self):
        inventory = build_inventory([])
        assert inventory.total == 0
        assert inventory.duplicate_count == 0

    def test_single_batch_single_endpoint(self):
        endpoints = [_make_endpoint("GET", "/api/users")]
        inventory = build_inventory([endpoints])
        assert inventory.total == 1
        assert inventory.duplicate_count == 0

    def test_multiple_batches_combined(self):
        batch1 = [_make_endpoint("GET", "/api/users", source="openapi")]
        batch2 = [_make_endpoint("GET", "/api/orders", source="endpoint_list")]
        inventory = build_inventory([batch1, batch2])
        assert inventory.total == 2

    def test_sources_used_populated(self):
        batch1 = [_make_endpoint("GET", "/api/users", source="openapi")]
        batch2 = [_make_endpoint("GET", "/api/orders", source="endpoint_list")]
        inventory = build_inventory([batch1, batch2])
        assert "openapi" in inventory.sources_used
        assert "endpoint_list" in inventory.sources_used

    def test_source_counts_correct(self):
        batch1 = [
            _make_endpoint("GET", "/api/users", source="openapi"),
            _make_endpoint("GET", "/api/orders", source="openapi"),
        ]
        batch2 = [
            _make_endpoint("GET", "/api/items", source="endpoint_list"),
        ]
        inventory = build_inventory([batch1, batch2])
        assert inventory.source_counts["openapi"] == 2
        assert inventory.source_counts["endpoint_list"] == 1


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_exact_duplicate_removed(self):
        eps = [
            _make_endpoint("GET", "/api/users", source="openapi"),
            _make_endpoint("GET", "/api/users", source="openapi"),
        ]
        inventory = build_inventory([eps])
        assert inventory.total == 1
        assert inventory.duplicate_count == 1

    def test_same_path_different_method_not_duplicate(self):
        eps = [
            _make_endpoint("GET", "/api/users"),
            _make_endpoint("POST", "/api/users"),
        ]
        inventory = build_inventory([eps])
        assert inventory.total == 2
        assert inventory.duplicate_count == 0

    def test_higher_priority_source_wins(self):
        # openapi (priority 0) should beat endpoint_list (priority 1)
        ep_openapi = _make_endpoint("GET", "/api/users", source="openapi")
        ep_list = _make_endpoint("GET", "/api/users", source="endpoint_list")
        inventory = build_inventory([[ep_list, ep_openapi]])
        assert inventory.total == 1
        assert inventory.endpoints[0].source == "openapi"

    def test_lower_priority_source_loses(self):
        ep_list = _make_endpoint("GET", "/api/users", source="endpoint_list")
        ep_openapi = _make_endpoint("GET", "/api/users", source="openapi")
        # Openapi first — endpoint_list duplicate should be dropped
        inventory = build_inventory([[ep_openapi, ep_list]])
        assert inventory.total == 1
        assert inventory.endpoints[0].source == "openapi"

    def test_concrete_id_paths_normalised_and_deduplicated(self):
        # /api/users/123 and /api/users/456 should normalize to same key
        ep1 = _make_endpoint("GET", "/api/users/123", source="endpoint_list")
        ep2 = _make_endpoint("GET", "/api/users/456", source="endpoint_list")
        inventory = build_inventory([[ep1, ep2]])
        assert inventory.total == 1
        assert inventory.endpoints[0].path == "/api/users/{id}"

    def test_templated_path_not_re_normalised(self):
        ep = _make_endpoint("GET", "/api/users/{user_id}", source="openapi")
        inventory = build_inventory([[ep]])
        assert inventory.total == 1
        assert inventory.endpoints[0].path == "/api/users/{user_id}"

    def test_cross_batch_deduplication(self):
        batch1 = [_make_endpoint("GET", "/api/users", source="openapi")]
        batch2 = [_make_endpoint("GET", "/api/users", source="endpoint_list")]
        inventory = build_inventory([batch1, batch2])
        assert inventory.total == 1
        assert inventory.duplicate_count == 1
        assert inventory.endpoints[0].source == "openapi"


# ---------------------------------------------------------------------------
# EndpointInventory properties
# ---------------------------------------------------------------------------


class TestEndpointInventoryProperties:
    def test_total_property(self):
        inventory = EndpointInventory(
            endpoints=[
                _make_endpoint("GET", "/a"),
                _make_endpoint("GET", "/b"),
            ]
        )
        assert inventory.total == 2

    def test_object_id_endpoint_count(self):
        ep_with_id = _make_endpoint(
            "GET", "/api/users/{user_id}", params=[_make_id_param("user_id")]
        )
        ep_without = _make_endpoint("GET", "/api/health")
        inventory = build_inventory([[ep_with_id, ep_without]])
        assert inventory.object_id_endpoint_count == 1

    def test_filter_by_method(self):
        batch = [
            _make_endpoint("GET", "/api/users"),
            _make_endpoint("POST", "/api/users"),
            _make_endpoint("GET", "/api/orders"),
        ]
        inventory = build_inventory([batch])
        gets = inventory.filter_by_method("GET")
        posts = inventory.filter_by_method("POST")
        assert len(gets) == 2
        assert len(posts) == 1

    def test_filter_by_source(self):
        batch1 = [_make_endpoint("GET", "/api/users", source="openapi")]
        batch2 = [_make_endpoint("GET", "/api/orders", source="endpoint_list")]
        inventory = build_inventory([batch1, batch2])
        openapi_eps = inventory.filter_by_source("openapi")
        list_eps = inventory.filter_by_source("endpoint_list")
        assert len(openapi_eps) == 1
        assert len(list_eps) == 1

    def test_summary_lines_returns_strings(self):
        batch = [_make_endpoint("GET", "/api/users", source="openapi")]
        inventory = build_inventory([batch])
        lines = inventory.summary_lines()
        assert isinstance(lines, list)
        assert all(isinstance(line, str) for line in lines)
        assert any("1" in line for line in lines)  # total count

    def test_empty_inventory_summary(self):
        inventory = EndpointInventory()
        lines = inventory.summary_lines()
        assert any("0" in line for line in lines)


# ---------------------------------------------------------------------------
# B2 fix — parameter re-inference after path normalization
# ---------------------------------------------------------------------------


class TestParameterReInferenceOnNormalization:
    """
    When a concrete path like /api/users/123 is normalized to /api/users/{id},
    the inventory must re-infer path parameters from the new template so that
    IDOR candidates are not silently dropped.
    """

    def test_concrete_path_gets_params_after_normalization(self):
        # endpoint_list parser produces no params for a concrete path
        ep = _make_endpoint("GET", "/api/users/123", source="endpoint_list")
        assert ep.parameters == []

        inventory = build_inventory([[ep]])
        assert inventory.total == 1
        result_ep = inventory.endpoints[0]

        # After normalization, the path template should be inferred
        assert result_ep.path == "/api/users/{id}"
        # And a path parameter named "id" should be present
        assert len(result_ep.parameters) == 1
        p = result_ep.parameters[0]
        assert p.name == "id"
        assert p.likely_object_id is True

    def test_openapi_params_preserved_on_normalization(self):
        # OpenAPI endpoints already have rich params — don't lose them
        ep = _make_endpoint(
            "GET",
            "/api/users/123",  # concrete path (unusual for OpenAPI but possible)
            source="openapi",
            params=[_make_id_param("user_id")],
        )
        inventory = build_inventory([[ep]])
        result_ep = inventory.endpoints[0]
        # OpenAPI params should be preserved, not replaced by inference
        assert any(p.name == "user_id" for p in result_ep.parameters)

    def test_normalized_endpoint_is_idor_candidate(self):
        ep = _make_endpoint("GET", "/api/orders/99", source="endpoint_list")
        inventory = build_inventory([[ep]])
        assert inventory.object_id_endpoint_count == 1

    def test_non_id_concrete_path_not_flagged(self):
        # /api/users/profile — "profile" is not numeric/UUID, stays as-is
        ep = _make_endpoint("GET", "/api/users/profile", source="endpoint_list")
        inventory = build_inventory([[ep]])
        result_ep = inventory.endpoints[0]
        assert result_ep.path == "/api/users/profile"
        assert result_ep.parameters == []
        assert inventory.object_id_endpoint_count == 0
