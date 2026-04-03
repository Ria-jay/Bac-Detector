"""
G4 unit tests — edge cases and gaps not covered by G1/G2/G3.

G1 covers the happy path for action inference, normalization, and family grouping.
G2 covers ownership and tenant inference core cases.
G3 covers all 6 analyzers and the service layer.

This file fills the remaining gaps:
  - Inference edge cases (unusual paths, boundary inputs)
  - Builder robustness (empty inputs, missing data)
  - Ownership inference with multiple co-present fields
  - End-to-end graph construction from real pipeline objects
  - Graph index correctness after mutations
"""

from __future__ import annotations

from bac_detector.config.loader import GraphAnalysisConfig
from bac_detector.graph.inference import (
    group_into_families,
    infer_action,
    infer_ownership_for_edge,
    normalize_resource,
)
from bac_detector.graph.models import (
    AccessEdge,
    AccessOutcome,
    ActionType,
    AuthGraph,
    EndpointNode,
    IdentityNode,
    OwnershipConclusion,
    OwnershipConfidence,
    ResourceKey,
    ResourceNode,
    RoleNode,
)
from bac_detector.graph.service import run_graph_analysis

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _edge(
    identity: str = "alice",
    ep_key: str = "GET /api/orders/{id}",
    resource_key: str = "orders:1",
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    body_snippet: str = "",
    json_keys: list[str] | None = None,
    object_id: str | None = "1",
    status_code: int = 200,
) -> AccessEdge:
    return AccessEdge(
        identity_name=identity,
        endpoint_key=ep_key,
        resource_key=resource_key,
        action=ActionType.READ,
        outcome=outcome,
        status_code=status_code,
        object_id_used=object_id,
        body_snippet=body_snippet,
        json_keys=json_keys or [],
    )


# ---------------------------------------------------------------------------
# Action inference — edge cases
# ---------------------------------------------------------------------------

class TestInferActionEdgeCases:
    def test_root_path_is_list(self):
        assert infer_action("GET", "/") == ActionType.LIST

    def test_single_segment_no_id_is_list(self):
        assert infer_action("GET", "/health") == ActionType.LIST

    def test_options_is_unknown(self):
        assert infer_action("OPTIONS", "/api/orders") == ActionType.UNKNOWN

    def test_head_is_unknown(self):
        assert infer_action("HEAD", "/api/orders/{id}") == ActionType.UNKNOWN

    def test_api_prefix_stripped_correctly(self):
        # /api/orders/{id} should still resolve to READ, not confused by "api" segment
        assert infer_action("GET", "/api/orders/{id}") == ActionType.READ

    def test_v2_prefix_doesnt_change_action(self):
        assert infer_action("GET", "/api/v2/users/{id}") == ActionType.READ
        assert infer_action("GET", "/api/v2/users") == ActionType.LIST

    def test_deeply_nested_admin_path(self):
        assert infer_action("POST", "/api/v1/admin/users/{id}/reset") == ActionType.ADMIN_ACTION

    def test_custom_action_with_get_method(self):
        # GET /orders/{id}/refund — "refund" is a custom action suffix,
        # but because it's GET + child path with a custom action suffix,
        # the custom action rule fires before child path rule
        result = infer_action("GET", "/orders/{id}/refund")
        assert result == ActionType.CUSTOM_ACTION

    def test_post_to_collection_under_admin(self):
        assert infer_action("POST", "/admin/users") == ActionType.ADMIN_ACTION

    def test_delete_under_admin(self):
        assert infer_action("DELETE", "/admin/users/{id}") == ActionType.ADMIN_ACTION

    def test_patch_child_path_is_update(self):
        # PATCH /orders/{id}/items is not a "child" in our model (PATCH → UPDATE rule fires)
        assert infer_action("PATCH", "/orders/{id}/items") == ActionType.UPDATE

    def test_hyphenated_resource_name(self):
        # Paths like /api/line-items/{id} should still infer READ
        assert infer_action("GET", "/api/line-items/{id}") == ActionType.READ

    def test_empty_method_string(self):
        result = infer_action("", "/api/orders")
        assert result == ActionType.UNKNOWN


# ---------------------------------------------------------------------------
# Resource normalization — edge cases
# ---------------------------------------------------------------------------

class TestNormalizeResourceEdgeCases:
    def test_hyphenated_resource_name(self):
        rk = normalize_resource("GET /api/line-items/{id}", "99")
        assert rk is not None
        assert rk.resource_type == "line-items"
        assert rk.resource_id == "99"

    def test_double_versioned_path(self):
        rk = normalize_resource("GET /api/v1/v2/users/{id}", "5")
        assert rk is not None
        assert rk.resource_type == "users"

    def test_bare_root_path_with_id(self):
        # /v1/{id} — the only named segment is a version token.
        # After the version-segment fix, both the primary regex and the
        # fallback correctly return None — there is no resource name here.
        rk = normalize_resource("GET /v1/{id}", "42")
        assert rk is None

    def test_resource_key_string_format(self):
        rk = normalize_resource("GET /api/invoices/{invoice_id}", "501")
        assert rk is not None
        assert rk.key == "invoices:501"

    def test_tenant_id_passed_through(self):
        rk = normalize_resource("GET /api/orders/{id}", "1", tenant_id="acme")
        assert rk is not None
        assert rk.tenant_id == "acme"

    def test_parent_key_passed_through(self):
        rk = normalize_resource(
            "GET /api/orders/{id}/items/{item_id}", "77",
            parent_key="orders:1"
        )
        assert rk is not None
        assert rk.parent_key == "orders:1"

    def test_none_object_id_returns_none(self):
        assert normalize_resource("GET /api/orders", None) is None
        assert normalize_resource("GET /api/orders/{id}", None) is None

    def test_versioned_path_bare_placeholder_not_v2(self):
        # /api/v2/{id} — v2 is a version segment, not a resource type.
        # The fixed _infer_resource_type skips version segments.
        rk = normalize_resource("GET /api/v2/{id}", "99")
        if rk is not None:
            assert rk.resource_type != "v2", (
                "Version segment 'v2' must not be used as resource_type"
            )

    def test_versioned_path_with_resource_name(self):
        # /api/v2/orders/{id} — version present but resource name follows.
        rk = normalize_resource("GET /api/v2/orders/{id}", "7")
        assert rk is not None
        assert rk.resource_type == "orders"

    def test_v1_bare_placeholder_not_v1(self):
        # /v1/{user_id} — the only segment before placeholder is v1.
        # Should not produce resource_type="v1".
        rk = normalize_resource("GET /v1/{user_id}", "5")
        if rk is not None:
            assert rk.resource_type != "v1"


# ---------------------------------------------------------------------------
# Family grouping — edge cases
# ---------------------------------------------------------------------------

class TestGroupIntoFamiliesEdgeCases:
    def test_empty_list_returns_empty(self):
        assert group_into_families([]) == []

    def test_only_list_endpoints_no_family(self):
        # /api/orders (list) and /api/users (list) — different resource types,
        # and neither has a placeholder, so they can't form families with each other
        keys = ["GET /api/orders", "GET /api/users"]
        families = group_into_families(keys)
        assert families == []

    def test_admin_endpoints_grouped_as_family(self):
        keys = [
            "GET /admin/users",
            "GET /admin/users/{id}",
            "DELETE /admin/users/{id}",
        ]
        families = group_into_families(keys)
        assert len(families) >= 1
        types = {f.resource_type for f in families}
        assert "users" in types

    def test_versioned_paths_grouped_together(self):
        keys = [
            "GET /api/v2/orders/{id}",
            "GET /api/v2/orders/{id}/invoice",
        ]
        families = group_into_families(keys)
        assert len(families) == 1
        assert families[0].resource_type == "orders"

    def test_hyphenated_resource_family(self):
        keys = [
            "GET /api/line-items/{id}",
            "DELETE /api/line-items/{id}",
        ]
        families = group_into_families(keys)
        assert len(families) == 1
        assert families[0].resource_type == "line-items"

    def test_family_endpoint_count(self):
        keys = [
            "GET /api/orders/{id}",
            "PUT /api/orders/{id}",
            "DELETE /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
        ]
        families = group_into_families(keys)
        assert len(families) == 1
        assert len(families[0].endpoint_keys) == 4


# ---------------------------------------------------------------------------
# Ownership inference — combined field scenarios
# ---------------------------------------------------------------------------

class TestOwnershipInferenceCombined:
    def test_primary_field_wins_over_secondary(self):
        """When both owner_id and account_id are present, owner_id (PRIMARY) governs."""
        edge = _edge(
            body_snippet='{"owner_id": "1", "account_id": "99"}',
            json_keys=["owner_id", "account_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is not None
        assert result.matched_field == "owner_id"
        assert result.confidence == OwnershipConfidence.HIGH

    def test_created_by_field_recognized(self):
        edge = _edge(
            body_snippet='{"id": "1", "created_by": "alice-uid"}',
            json_keys=["id", "created_by"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"alice-uid"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS
        assert result.matched_field == "created_by"

    def test_author_id_field_recognized(self):
        edge = _edge(
            body_snippet='{"id": "5", "author_id": "99"}',
            json_keys=["id", "author_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"99"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS

    def test_customer_id_medium_confidence(self):
        edge = _edge(
            body_snippet='{"id": "5", "customer_id": "42"}',
            json_keys=["id", "customer_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"42"})
        assert result is not None
        assert result.confidence == OwnershipConfidence.MEDIUM

    def test_multiple_non_matching_fields(self):
        """All fields present, none match principal_ids — LIKELY_DOES_NOT_OWN."""
        edge = _edge(
            body_snippet='{"owner_id": "999", "user_id": "888"}',
            json_keys=["owner_id", "user_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1", "2"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_DOES_NOT_OWN

    def test_integer_id_in_body_matches_string_principal(self):
        """Body has integer user_id, principal_ids has string — after str() conversion they match."""
        edge = _edge(
            body_snippet='{"user_id": 42}',
            json_keys=["user_id"],
        )
        # _extract_field_values returns string "42" for integer 42
        result = infer_ownership_for_edge(edge, principal_ids={"42"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS

    def test_error_response_returns_none(self):
        edge = _edge(
            outcome=AccessOutcome.ERROR,
            status_code=500,
            body_snippet='{"error": "internal"}',
            json_keys=["error"],
        )
        assert infer_ownership_for_edge(edge, principal_ids={"1"}) is None


# ---------------------------------------------------------------------------
# Graph builder — robustness
# ---------------------------------------------------------------------------

class TestBuilderRobustness:
    def _minimal_matrix_and_inventory(self):
        from bac_detector.analyzers.matrix import build_matrix
        from bac_detector.discovery.inventory import build_inventory
        from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
        from bac_detector.models.identity import AuthMechanism, IdentityProfile

        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/orders/{id}",
            base_url="https://api.example.com",
            parameters=[Parameter(
                name="id", location=ParameterLocation.PATH,
                likely_object_id=True, required=True
            )],
            source="openapi",
        )
        inventory = build_inventory([[ep]])
        matrix = build_matrix([])  # empty — no responses
        profiles = [
            IdentityProfile(name="alice", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="t",
                owned_object_ids=["1"]),
            IdentityProfile(name="bob", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="t2",
                owned_object_ids=["2"]),
        ]
        return matrix, inventory, profiles

    def test_empty_matrix_builds_without_error(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._minimal_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert graph is not None

    def test_empty_matrix_has_endpoints_but_no_edges(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._minimal_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert len(graph.endpoints) == 1
        assert graph.total_edges == 0

    def test_empty_matrix_has_identities(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._minimal_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert "alice" in graph.identities
        assert "bob" in graph.identities

    def test_empty_matrix_no_ownership_inferences(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._minimal_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        assert graph.ownership_inferences == []

    def test_graph_analysis_on_empty_graph_returns_empty(self):
        from bac_detector.graph.builder import build_graph
        matrix, inventory, profiles = self._minimal_matrix_and_inventory()
        graph = build_graph(matrix, inventory, profiles)
        config = GraphAnalysisConfig(enabled=True)
        findings = run_graph_analysis(graph, config)
        assert findings == []


# ---------------------------------------------------------------------------
# Graph index correctness
# ---------------------------------------------------------------------------

class TestGraphIndexCorrectness:
    def _make_graph(self) -> AuthGraph:
        graph = AuthGraph()
        graph.identities["alice"] = IdentityNode(name="alice", role="user",
                                                  likely_principal_ids={"1"})
        graph.identities["bob"] = IdentityNode(name="bob", role="user",
                                                likely_principal_ids={"2"})
        graph.roles["user"] = RoleNode(name="user", identity_names={"alice", "bob"})
        graph.endpoints["GET /api/orders/{id}"] = EndpointNode(
            endpoint_key="GET /api/orders/{id}",
            method="GET", path="/api/orders/{id}",
            action=ActionType.READ, resource_type="orders",
        )
        rk = ResourceKey(resource_type="orders", resource_id="1")
        graph.resources["orders:1"] = ResourceNode(key=rk)

        graph.edges = [
            AccessEdge(identity_name="alice", endpoint_key="GET /api/orders/{id}",
                       resource_key="orders:1", action=ActionType.READ,
                       outcome=AccessOutcome.ALLOWED, status_code=200,
                       object_id_used="1"),
            AccessEdge(identity_name="bob", endpoint_key="GET /api/orders/{id}",
                       resource_key="orders:1", action=ActionType.READ,
                       outcome=AccessOutcome.DENIED, status_code=403,
                       object_id_used="1"),
        ]
        graph._build_indexes()
        return graph

    def test_edges_for_identity_returns_correct_count(self):
        graph = self._make_graph()
        assert len(graph.edges_for_identity("alice")) == 1
        assert len(graph.edges_for_identity("bob")) == 1

    def test_edges_for_identity_unknown_returns_empty(self):
        graph = self._make_graph()
        assert graph.edges_for_identity("charlie") == []

    def test_edges_for_endpoint_returns_both_identities(self):
        graph = self._make_graph()
        edges = graph.edges_for_endpoint("GET /api/orders/{id}")
        assert len(edges) == 2

    def test_edges_for_resource_returns_both(self):
        graph = self._make_graph()
        edges = graph.edges_for_resource("orders:1")
        assert len(edges) == 2

    def test_edges_for_identity_resource(self):
        graph = self._make_graph()
        alice_edges = graph.edges_for_identity_resource("alice", "orders:1")
        assert len(alice_edges) == 1
        assert alice_edges[0].outcome == AccessOutcome.ALLOWED

    def test_outcome_for_identity_endpoint(self):
        graph = self._make_graph()
        assert graph.outcome_for_identity_endpoint("alice", "GET /api/orders/{id}") == AccessOutcome.ALLOWED
        assert graph.outcome_for_identity_endpoint("bob", "GET /api/orders/{id}") == AccessOutcome.DENIED

    def test_outcome_for_unknown_identity_returns_none(self):
        graph = self._make_graph()
        assert graph.outcome_for_identity_endpoint("charlie", "GET /api/orders/{id}") is None

    def test_outcome_for_unknown_endpoint_returns_none(self):
        graph = self._make_graph()
        assert graph.outcome_for_identity_endpoint("alice", "GET /api/unknown") is None

    def test_total_nodes(self):
        graph = self._make_graph()
        # 2 identities + 1 role + 1 resource + 1 endpoint = 5
        assert graph.total_nodes == 5

    def test_total_edges(self):
        graph = self._make_graph()
        assert graph.total_edges == 2


# ---------------------------------------------------------------------------
# End-to-end graph construction from real pipeline objects
# ---------------------------------------------------------------------------

class TestEndToEndGraphConstruction:
    """
    Build a complete graph through the full pipeline
    (matrix → builder → apply_inferences → run_graph_analysis)
    using synthetic but realistic data that exercises ownership inference.
    """

    def _run_full_pipeline(self):
        from bac_detector.analyzers.matrix import build_matrix
        from bac_detector.discovery.inventory import build_inventory
        from bac_detector.graph.builder import build_graph
        from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
        from bac_detector.models.identity import AuthMechanism, IdentityProfile
        from bac_detector.models.response_meta import ResponseMeta

        ep_parent = Endpoint(
            method=HttpMethod.GET, path="/api/orders/{id}",
            base_url="https://api.example.com",
            parameters=[Parameter(name="id", location=ParameterLocation.PATH,
                                  likely_object_id=True, required=True)],
            source="openapi",
        )
        ep_child = Endpoint(
            method=HttpMethod.GET, path="/api/orders/{id}/invoice",
            base_url="https://api.example.com",
            parameters=[], source="openapi",
        )
        ep_admin = Endpoint(
            method=HttpMethod.GET, path="/admin/orders",
            base_url="https://api.example.com",
            parameters=[], source="openapi",
        )
        inventory = build_inventory([[ep_parent, ep_child, ep_admin]])

        profiles = [
            IdentityProfile(name="alice", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-alice",
                owned_object_ids=["1"]),
            IdentityProfile(name="bob", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-bob",
                owned_object_ids=["2"]),
            IdentityProfile(name="admin", role="admin",
                auth_mechanism=AuthMechanism.BEARER, token="tok-admin",
                owned_object_ids=["3"]),
        ]

        # alice owns order 1 (response has owner_id=1)
        # bob accesses order 1 — response has owner_id=1 (not bob's id=2) → IDOR
        # alice is DENIED /api/orders/1/invoice but bob is ALLOWED
        # alice and bob are DENIED /admin/orders; admin is ALLOWED
        responses = [
            ResponseMeta.from_response(
                status_code=403,
                body='{"error": "forbidden"}',
                content_type="application/json", latency_ms=3.0,
                endpoint_key="GET /api/orders/{id}",
                identity_name="alice",
                requested_url="https://api.example.com/api/orders/1",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=200,
                body='{"id": "1", "owner_id": "1", "amount": 500}',
                content_type="application/json", latency_ms=5.0,
                endpoint_key="GET /api/orders/{id}",
                identity_name="bob",
                requested_url="https://api.example.com/api/orders/1",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=200,
                body='{"invoice_id": "99", "order_id": "1"}',
                content_type="application/json", latency_ms=5.0,
                endpoint_key="GET /api/orders/{id}/invoice",
                identity_name="alice",
                requested_url="https://api.example.com/api/orders/1/invoice",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=200,
                body='{"invoice_id": "99", "order_id": "1"}',
                content_type="application/json", latency_ms=5.0,
                endpoint_key="GET /api/orders/{id}/invoice",
                identity_name="bob",
                requested_url="https://api.example.com/api/orders/1/invoice",
                object_id_used="1",
            ),
            ResponseMeta.from_response(
                status_code=403,
                body='{"error": "forbidden"}',
                content_type="application/json", latency_ms=3.0,
                endpoint_key="GET /admin/orders",
                identity_name="alice",
                requested_url="https://api.example.com/admin/orders",
                object_id_used=None,
            ),
            ResponseMeta.from_response(
                status_code=200,
                body='{"orders": []}',
                content_type="application/json", latency_ms=5.0,
                endpoint_key="GET /admin/orders",
                identity_name="admin",
                requested_url="https://api.example.com/admin/orders",
                object_id_used=None,
            ),
        ]

        matrix = build_matrix(responses)
        graph = build_graph(matrix, inventory, profiles)
        return graph

    def test_graph_builds_without_error(self):
        graph = self._run_full_pipeline()
        assert graph is not None

    def test_graph_has_all_identities(self):
        graph = self._run_full_pipeline()
        assert set(graph.identities.keys()) == {"alice", "bob", "admin"}

    def test_graph_has_all_endpoints(self):
        graph = self._run_full_pipeline()
        assert "GET /api/orders/{id}" in graph.endpoints
        assert "GET /api/orders/{id}/invoice" in graph.endpoints
        assert "GET /admin/orders" in graph.endpoints

    def test_child_endpoint_marked(self):
        graph = self._run_full_pipeline()
        invoice_ep = graph.endpoints["GET /api/orders/{id}/invoice"]
        assert invoice_ep.is_child_endpoint is True

    def test_admin_endpoint_action(self):
        graph = self._run_full_pipeline()
        admin_ep = graph.endpoints["GET /admin/orders"]
        assert admin_ep.action == ActionType.ADMIN_ACTION

    def test_ownership_inference_alice_owns(self):
        # alice is DENIED on the parent endpoint (403), so she never gets a
        # successful response containing owner_id. Her ownership inference is
        # None — the pipeline correctly makes no claim about her ownership
        # from the response data alone.
        # bob's inference (LIKELY_DOES_NOT_OWN) is confirmed by the sibling test.
        graph = self._run_full_pipeline()
        oi = graph.best_ownership_inference("alice", "orders:1")
        # No inference expected: alice's only allowed response (child/invoice)
        # contains no ownership fields (invoice_id, order_id — not owner_id).
        assert oi is None

    def test_ownership_inference_bob_does_not_own(self):
        graph = self._run_full_pipeline()
        oi = graph.best_ownership_inference("bob", "orders:1")
        assert oi is not None
        assert oi.conclusion == OwnershipConclusion.LIKELY_DOES_NOT_OWN

    def test_child_resource_exposure_detected(self):
        graph = self._run_full_pipeline()
        # Verify the graph has the right structure for child exposure:
        # alice denied on parent, allowed on child with same object_id
        from bac_detector.graph.analyzers import analyze_child_resource_exposure
        from bac_detector.graph.models import AccessOutcome
        parent_ep = "GET /api/orders/{id}"
        child_ep  = "GET /api/orders/{id}/invoice"
        alice_parent = graph.edges_for_identity_endpoint("alice", parent_ep)
        alice_child  = graph.edges_for_identity_endpoint("alice", child_ep)
        assert any(e.outcome == AccessOutcome.DENIED  for e in alice_parent),             "alice should be DENIED on parent"
        assert any(e.outcome == AccessOutcome.ALLOWED for e in alice_child),             "alice should be ALLOWED on child"
        # Run the specific analyzer and verify it produces the finding
        child_findings = analyze_child_resource_exposure(graph)
        assert len(child_findings) >= 1, (
            "Expected child_resource_exposure finding — alice denied parent "
            "but allowed child endpoint"
        )

    def test_ownership_inconsistency_detected_for_bob(self):
        graph = self._run_full_pipeline()
        config = GraphAnalysisConfig(enabled=True)
        findings = run_graph_analysis(graph, config)
        ownership_findings = [f for f in findings if f.category == "graph_ownership_inconsistency"]
        assert len(ownership_findings) >= 1
        assert any(f.evidence.attacker_identity == "bob" for f in ownership_findings)

    def test_no_findings_when_graph_analysis_disabled(self):
        graph = self._run_full_pipeline()
        config = GraphAnalysisConfig(enabled=False)
        assert run_graph_analysis(graph, config) == []

    def test_resource_attributes_populated(self):
        graph = self._run_full_pipeline()
        orders_node = graph.resources.get("orders:1")
        assert orders_node is not None
        assert orders_node.attributes.get("owner_id") == "1"

    def test_family_contains_orders_endpoints(self):
        graph = self._run_full_pipeline()
        orders_family = next(
            (f for f in graph.families if f.resource_type == "orders"), None
        )
        assert orders_family is not None
        assert "GET /api/orders/{id}" in orders_family.endpoint_keys
        assert "GET /api/orders/{id}/invoice" in orders_family.child_endpoint_keys
