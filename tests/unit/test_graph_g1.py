"""
Unit tests for Authorization Graph Engine — G1.

Covers:
- Action inference (infer_action)
- Resource normalization (normalize_resource)
- Resource family grouping (group_into_families)
- Parent-child inference (infer_parent_child)
- Graph builder integration (build_graph)
"""

from __future__ import annotations

from bac_detector.graph.inference import (
    group_into_families,
    infer_action,
    infer_parent_child,
    normalize_resource,
)
from bac_detector.graph.models import (
    AccessOutcome,
    ActionType,
)

# ---------------------------------------------------------------------------
# Action inference
# ---------------------------------------------------------------------------

class TestInferAction:
    # Standard CRUD
    def test_get_with_id_is_read(self):
        assert infer_action("GET", "/api/orders/{id}") == ActionType.READ

    def test_get_without_id_is_list(self):
        assert infer_action("GET", "/api/orders") == ActionType.LIST

    def test_post_without_id_is_create(self):
        assert infer_action("POST", "/api/orders") == ActionType.CREATE

    def test_put_is_update(self):
        assert infer_action("PUT", "/api/orders/{id}") == ActionType.UPDATE

    def test_patch_is_update(self):
        assert infer_action("PATCH", "/api/orders/{id}") == ActionType.UPDATE

    def test_delete_is_delete(self):
        assert infer_action("DELETE", "/api/orders/{id}") == ActionType.DELETE

    # Child / sub-resource
    def test_get_child_resource_is_read_child(self):
        assert infer_action("GET", "/api/orders/{id}/invoice") == ActionType.READ_CHILD

    def test_get_nested_child_is_read_child(self):
        assert infer_action("GET", "/api/orders/{id}/items") == ActionType.READ_CHILD

    def test_post_child_resource_is_create_child(self):
        assert infer_action("POST", "/api/orders/{id}/items") == ActionType.CREATE_CHILD

    # Custom actions
    def test_post_refund_is_custom(self):
        assert infer_action("POST", "/api/orders/{id}/refund") == ActionType.CUSTOM_ACTION

    def test_post_cancel_is_custom(self):
        assert infer_action("POST", "/api/orders/{id}/cancel") == ActionType.CUSTOM_ACTION

    def test_post_disable_is_custom(self):
        assert infer_action("POST", "/api/users/{id}/disable") == ActionType.CUSTOM_ACTION

    # Admin paths
    def test_admin_segment_is_admin_action(self):
        assert infer_action("GET", "/admin/users") == ActionType.ADMIN_ACTION

    def test_admin_with_id_is_admin_action(self):
        assert infer_action("GET", "/admin/users/{id}") == ActionType.ADMIN_ACTION

    def test_internal_segment_is_admin_action(self):
        assert infer_action("GET", "/api/internal/stats") == ActionType.ADMIN_ACTION

    def test_delete_on_admin_path_is_admin_action(self):
        assert infer_action("DELETE", "/admin/users/{id}") == ActionType.ADMIN_ACTION

    # Case insensitivity
    def test_lowercase_method(self):
        assert infer_action("get", "/api/orders/{id}") == ActionType.READ

    # Health / misc
    def test_health_is_list(self):
        assert infer_action("GET", "/health") == ActionType.LIST

    def test_unknown_method(self):
        assert infer_action("OPTIONS", "/api/orders") == ActionType.UNKNOWN


# ---------------------------------------------------------------------------
# Resource normalization
# ---------------------------------------------------------------------------

class TestNormalizeResource:
    def test_simple_resource(self):
        rk = normalize_resource("GET /api/orders/{id}", "1001")
        assert rk is not None
        assert rk.resource_type == "orders"
        assert rk.resource_id == "1001"
        assert str(rk) == "orders:1001"

    def test_user_resource(self):
        rk = normalize_resource("GET /api/users/{user_id}", "42")
        assert rk is not None
        assert rk.resource_type == "users"
        assert rk.resource_id == "42"

    def test_child_endpoint_maps_to_parent_type(self):
        # /orders/{id}/invoice should still map to orders type
        rk = normalize_resource("GET /api/orders/{id}/invoice", "1001")
        assert rk is not None
        assert rk.resource_type == "orders"
        assert rk.resource_id == "1001"

    def test_no_object_id_returns_none(self):
        rk = normalize_resource("GET /api/orders", None)
        assert rk is None

    def test_with_parent_key(self):
        rk = normalize_resource(
            "GET /api/orders/{id}/items/{item_id}", "99",
            parent_key="orders:1001"
        )
        assert rk is not None
        assert rk.parent_key == "orders:1001"

    def test_key_format(self):
        rk = normalize_resource("GET /api/invoices/{id}", "501")
        assert rk is not None
        assert rk.key == "invoices:501"

    def test_versioned_path(self):
        rk = normalize_resource("GET /api/v2/users/{id}", "7")
        assert rk is not None
        assert rk.resource_type == "users"


# ---------------------------------------------------------------------------
# Resource family grouping
# ---------------------------------------------------------------------------

class TestGroupIntoFamilies:
    def test_single_endpoint_no_family(self):
        # A lone endpoint has nothing to compare against
        families = group_into_families(["GET /api/orders/{id}"])
        assert families == []

    def test_parent_and_child_form_family(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        families = group_into_families(keys)
        assert len(families) == 1
        f = families[0]
        assert f.resource_type == "orders"
        assert "GET /api/orders/{id}" in f.endpoint_keys
        assert "GET /api/orders/{id}/invoice" in f.endpoint_keys

    def test_multiple_children_same_family(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
            "POST /api/orders/{id}/refund",
            "GET /api/orders/{id}/items",
        ]
        families = group_into_families(keys)
        order_family = next((f for f in families if f.resource_type == "orders"), None)
        assert order_family is not None
        assert len(order_family.endpoint_keys) == 4

    def test_separate_families_not_merged(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
            "GET /api/users/{id}",
            "GET /api/users/{id}/profile",
        ]
        families = group_into_families(keys)
        types = {f.resource_type for f in families}
        assert "orders" in types
        assert "users" in types

    def test_parent_child_split(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        families = group_into_families(keys)
        f = families[0]
        assert "GET /api/orders/{id}" in f.parent_endpoint_keys
        assert "GET /api/orders/{id}/invoice" in f.child_endpoint_keys

    def test_list_endpoint_grouped_with_resource(self):
        keys = [
            "GET /api/orders",
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        families = group_into_families(keys)
        assert len(families) == 1
        f = families[0]
        assert len(f.endpoint_keys) == 3


# ---------------------------------------------------------------------------
# Parent-child inference
# ---------------------------------------------------------------------------

class TestInferParentChild:
    def test_child_mapped_to_parent(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        result = infer_parent_child(keys)
        assert "GET /api/orders/{id}/invoice" in result
        assert result["GET /api/orders/{id}/invoice"] == "GET /api/orders/{id}"

    def test_multiple_children_same_parent(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
            "GET /api/orders/{id}/items",
        ]
        result = infer_parent_child(keys)
        assert "GET /api/orders/{id}/invoice" in result
        assert "GET /api/orders/{id}/items" in result

    def test_parent_not_in_result_as_child(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        result = infer_parent_child(keys)
        assert "GET /api/orders/{id}" not in result

    def test_no_children_empty_result(self):
        keys = [
            "GET /api/orders/{id}",
            "GET /api/users/{id}",
        ]
        result = infer_parent_child(keys)
        assert result == {}

    def test_list_endpoint_not_a_child(self):
        keys = [
            "GET /api/orders",
            "GET /api/orders/{id}",
        ]
        result = infer_parent_child(keys)
        assert "GET /api/orders" not in result


# ---------------------------------------------------------------------------
# Graph builder integration smoke test
# ---------------------------------------------------------------------------

class TestBuildGraph:
    def _make_matrix_and_inventory(self):
        """Build minimal matrix + inventory for builder testing."""
        from bac_detector.analyzers.matrix import build_matrix
        from bac_detector.discovery.inventory import build_inventory
        from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
        from bac_detector.models.identity import AuthMechanism, IdentityProfile
        from bac_detector.models.response_meta import ResponseMeta

        # Build a minimal 2-endpoint inventory
        ep1 = Endpoint(
            method=HttpMethod.GET,
            path="/api/orders/{id}",
            base_url="https://api.example.com",
            parameters=[Parameter(
                name="id", location=ParameterLocation.PATH,
                likely_object_id=True, required=True
            )],
            source="openapi",
        )
        ep2 = Endpoint(
            method=HttpMethod.GET,
            path="/api/orders/{id}/invoice",
            base_url="https://api.example.com",
            parameters=[],
            source="openapi",
        )
        inventory = build_inventory([[ep1, ep2]])

        # Build responses: alice owns order 1, bob accesses it (IDOR)
        responses = [
            ResponseMeta.from_response(
                status_code=200, body='{"id":"1","owner":"alice"}',
                content_type="application/json", latency_ms=10.0,
                endpoint_key="GET /api/orders/{id}",
                identity_name="alice", requested_url="https://api.example.com/api/orders/1",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=200, body='{"id":"1","owner":"alice"}',
                content_type="application/json", latency_ms=10.0,
                endpoint_key="GET /api/orders/{id}",
                identity_name="bob", requested_url="https://api.example.com/api/orders/1",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=403, body='{"error":"forbidden"}',
                content_type="application/json", latency_ms=5.0,
                endpoint_key="GET /api/orders/{id}/invoice",
                identity_name="alice", requested_url="https://api.example.com/api/orders/1/invoice",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=200, body='{"invoice_id":"99"}',
                content_type="application/json", latency_ms=10.0,
                endpoint_key="GET /api/orders/{id}/invoice",
                identity_name="bob", requested_url="https://api.example.com/api/orders/1/invoice",
                object_id_used="1",
            ),
        ]
        matrix = build_matrix(responses)

        profiles = [
            IdentityProfile(name="alice", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-alice",
                owned_object_ids=["1"]),
            IdentityProfile(name="bob", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-bob",
                owned_object_ids=["2"]),
        ]
        return matrix, inventory, profiles

    def test_graph_has_expected_identities(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert "alice" in graph.identities
        assert "bob" in graph.identities

    def test_graph_has_expected_endpoints(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert "GET /api/orders/{id}" in graph.endpoints
        assert "GET /api/orders/{id}/invoice" in graph.endpoints

    def test_graph_has_edges(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert graph.total_edges >= 4

    def test_graph_detects_child_endpoint(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        invoice_ep = graph.endpoints.get("GET /api/orders/{id}/invoice")
        assert invoice_ep is not None
        assert invoice_ep.is_child_endpoint is True

    def test_graph_has_family(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert len(graph.families) >= 1
        assert any(f.resource_type == "orders" for f in graph.families)

    def test_access_edges_have_correct_outcomes(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)

        # bob: ALLOWED on parent endpoint
        bob_parent = graph.edges_for_identity_endpoint("bob", "GET /api/orders/{id}")
        assert any(e.outcome == AccessOutcome.ALLOWED for e in bob_parent)

        # alice: DENIED on invoice endpoint
        alice_invoice = graph.edges_for_identity_endpoint("alice", "GET /api/orders/{id}/invoice")
        assert any(e.outcome == AccessOutcome.DENIED for e in alice_invoice)

    def test_resource_nodes_created(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert "orders:1" in graph.resources

    def test_endpoint_action_inferred(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._make_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        parent_ep = graph.endpoints["GET /api/orders/{id}"]
        assert parent_ep.action == ActionType.READ
        child_ep = graph.endpoints["GET /api/orders/{id}/invoice"]
        assert child_ep.action == ActionType.READ_CHILD
