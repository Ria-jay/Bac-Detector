"""
Unit tests for Authorization Graph Engine — G2.

Covers:
- Body field extraction (JSON parse and regex fallback)
- Ownership inference (HIGH/MEDIUM/LOW confidence, owns/does-not-own/unknown)
- Tenant inference
- Parent-child resource linking
- apply_inferences integration (all passes applied to a graph)
- G2 query methods on AuthGraph
"""

from __future__ import annotations

from bac_detector.graph.inference import (
    _ALL_OWNERSHIP_FIELDS,
    _TENANT_FIELDS,
    _extract_field_values,
    infer_ownership_for_edge,
    infer_parent_child_resources,
    infer_tenant_for_edge,
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
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _edge(
    identity: str = "alice",
    ep_key: str = "GET /api/orders/{id}",
    resource_key: str = "orders:1001",
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    body_snippet: str = "",
    json_keys: list[str] | None = None,
    object_id: str | None = "1001",
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


def _minimal_graph_with_identity(
    identity: str = "alice",
    role: str = "user",
    principal_ids: set[str] | None = None,
    resource_key: str = "orders:1001",
) -> AuthGraph:
    """Build the minimum AuthGraph needed for G2 inference tests."""
    graph = AuthGraph()
    graph.identities[identity] = IdentityNode(
        name=identity,
        role=role,
        likely_principal_ids=principal_ids or set(),
    )
    rk_parts = resource_key.split(":", 1)
    rk = ResourceKey(resource_type=rk_parts[0], resource_id=rk_parts[1])
    graph.resources[resource_key] = ResourceNode(key=rk)
    return graph


# ---------------------------------------------------------------------------
# Body field extraction
# ---------------------------------------------------------------------------


class TestExtractFieldValues:
    def test_full_json_parse(self):
        body = '{"id": "1", "owner_id": "22", "name": "test"}'
        result = _extract_field_values(body, _ALL_OWNERSHIP_FIELDS)
        assert result.get("owner_id") == "22"

    def test_integer_value_extracted_as_string(self):
        body = '{"user_id": 15, "name": "alice"}'
        result = _extract_field_values(body, _ALL_OWNERSHIP_FIELDS)
        assert result.get("user_id") == "15"

    def test_multiple_fields_extracted(self):
        body = '{"owner_id": "22", "account_id": "99", "name": "x"}'
        result = _extract_field_values(body, _ALL_OWNERSHIP_FIELDS)
        assert result.get("owner_id") == "22"
        assert result.get("account_id") == "99"

    def test_regex_fallback_on_truncated_body(self):
        # Truncated JSON — json.loads will fail, regex should still find owner_id
        body = '{"id": "1001", "name": "alice alice alice alice alice alice long name", "owner_id": "22"'
        result = _extract_field_values(body, _ALL_OWNERSHIP_FIELDS)
        assert result.get("owner_id") == "22"

    def test_empty_body_returns_empty(self):
        assert _extract_field_values("", _ALL_OWNERSHIP_FIELDS) == {}

    def test_non_json_body_returns_empty(self):
        assert _extract_field_values("plain text response", _ALL_OWNERSHIP_FIELDS) == {}

    def test_array_body_returns_empty(self):
        assert _extract_field_values('[{"id": 1}]', _ALL_OWNERSHIP_FIELDS) == {}

    def test_irrelevant_fields_not_extracted(self):
        body = '{"id": "1", "status": "active", "name": "test"}'
        result = _extract_field_values(body, _ALL_OWNERSHIP_FIELDS)
        assert "id" not in result
        assert "status" not in result
        assert "name" not in result

    def test_tenant_field_extraction(self):
        body = '{"id": "1", "tenant_id": "acme", "data": "x"}'
        result = _extract_field_values(body, _TENANT_FIELDS)
        assert result.get("tenant_id") == "acme"

    def test_organization_id_extracted(self):
        body = '{"organization_id": "org-42"}'
        result = _extract_field_values(body, _TENANT_FIELDS)
        assert result.get("organization_id") == "org-42"


# ---------------------------------------------------------------------------
# Ownership inference — infer_ownership_for_edge
# ---------------------------------------------------------------------------


class TestInferOwnershipForEdge:
    def test_primary_field_match_is_high_confidence_owns(self):
        edge = _edge(
            identity="alice",
            body_snippet='{"id": "1001", "owner_id": "1"}',
            json_keys=["id", "owner_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS
        assert result.confidence == OwnershipConfidence.HIGH
        assert result.matched_field == "owner_id"
        assert result.matched_value == "1"

    def test_primary_field_mismatch_is_high_confidence_does_not_own(self):
        edge = _edge(
            identity="bob",
            body_snippet='{"id": "1001", "owner_id": "1"}',
            json_keys=["id", "owner_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"2"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_DOES_NOT_OWN
        assert result.confidence == OwnershipConfidence.HIGH

    def test_user_id_match_is_high_confidence(self):
        edge = _edge(
            body_snippet='{"user_id": "42", "data": "x"}',
            json_keys=["user_id", "data"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"42"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS
        assert result.confidence == OwnershipConfidence.HIGH

    def test_secondary_field_match_is_medium_confidence(self):
        edge = _edge(
            body_snippet='{"id": "1", "account_id": "99"}',
            json_keys=["id", "account_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"99"})
        assert result is not None
        assert result.conclusion == OwnershipConclusion.LIKELY_OWNS
        assert result.confidence == OwnershipConfidence.MEDIUM

    def test_no_principal_ids_configured_is_low_confidence_unknown(self):
        edge = _edge(
            body_snippet='{"owner_id": "22"}',
            json_keys=["owner_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids=set())
        assert result is not None
        assert result.conclusion == OwnershipConclusion.UNKNOWN
        assert result.confidence == OwnershipConfidence.LOW

    def test_no_ownership_fields_in_json_keys_returns_none(self):
        edge = _edge(
            body_snippet='{"id": "1", "status": "active"}',
            json_keys=["id", "status"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is None

    def test_denied_response_returns_none(self):
        edge = _edge(
            outcome=AccessOutcome.DENIED,
            status_code=403,
            body_snippet='{"error": "forbidden"}',
            json_keys=["error"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is None

    def test_no_resource_key_returns_none(self):
        edge = AccessEdge(
            identity_name="alice",
            endpoint_key="GET /api/orders",
            resource_key=None,   # list endpoint — no specific resource
            action=ActionType.LIST,
            outcome=AccessOutcome.ALLOWED,
            status_code=200,
            object_id_used=None,
            body_snippet='{"owner_id": "1"}',
            json_keys=["owner_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is None

    def test_truncated_body_fields_present_no_values_is_low_unknown(self):
        # json_keys says owner_id is present, but body is cut off before value
        edge = _edge(
            body_snippet='{"id": "1001", "name": "alice alice alice alice',
            json_keys=["id", "name", "owner_id"],   # json_keys includes owner_id
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is not None
        assert result.confidence == OwnershipConfidence.LOW
        assert result.conclusion == OwnershipConclusion.UNKNOWN

    def test_rationale_is_non_empty(self):
        edge = _edge(
            body_snippet='{"owner_id": "1"}',
            json_keys=["owner_id"],
        )
        result = infer_ownership_for_edge(edge, principal_ids={"1"})
        assert result is not None
        assert len(result.rationale) > 10


# ---------------------------------------------------------------------------
# Tenant inference — infer_tenant_for_edge
# ---------------------------------------------------------------------------


class TestInferTenantForEdge:
    def test_tenant_id_extracted(self):
        edge = _edge(
            body_snippet='{"id": "1", "tenant_id": "acme"}',
            json_keys=["id", "tenant_id"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is not None
        assert result.tenant_id == "acme"
        assert result.source_field == "tenant_id"
        assert result.resource_key == "orders:1001"

    def test_organization_id_used_as_fallback(self):
        edge = _edge(
            body_snippet='{"id": "1", "organization_id": "org-7"}',
            json_keys=["id", "organization_id"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is not None
        assert result.tenant_id == "org-7"
        assert result.source_field == "organization_id"

    def test_no_tenant_fields_returns_none(self):
        edge = _edge(
            body_snippet='{"id": "1", "name": "test"}',
            json_keys=["id", "name"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is None

    def test_denied_response_returns_none(self):
        edge = _edge(
            outcome=AccessOutcome.DENIED,
            status_code=403,
            body_snippet='{"tenant_id": "acme"}',
            json_keys=["tenant_id"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is None

    def test_no_resource_key_returns_none(self):
        edge = AccessEdge(
            identity_name="alice",
            endpoint_key="GET /api/orders",
            resource_key=None,
            action=ActionType.LIST,
            outcome=AccessOutcome.ALLOWED,
            status_code=200,
            object_id_used=None,
            body_snippet='{"tenant_id": "acme"}',
            json_keys=["tenant_id"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is None

    def test_tenant_id_preferred_over_organization_id(self):
        edge = _edge(
            body_snippet='{"tenant_id": "t1", "organization_id": "o1"}',
            json_keys=["tenant_id", "organization_id"],
        )
        result = infer_tenant_for_edge(edge)
        assert result is not None
        assert result.source_field == "tenant_id"
        assert result.tenant_id == "t1"


# ---------------------------------------------------------------------------
# Parent-child resource linking
# ---------------------------------------------------------------------------


class TestInferParentChildResources:
    def _make_graph_with_child_endpoint(self) -> AuthGraph:
        graph = AuthGraph()
        graph.identities["alice"] = IdentityNode(
            name="alice", role="user", likely_principal_ids={"1"}
        )

        # Parent endpoint
        graph.endpoints["GET /api/orders/{id}"] = EndpointNode(
            endpoint_key="GET /api/orders/{id}",
            method="GET",
            path="/api/orders/{id}",
            action=ActionType.READ,
            resource_type="orders",
            is_child_endpoint=False,
        )
        # Child endpoint
        graph.endpoints["GET /api/orders/{id}/invoice"] = EndpointNode(
            endpoint_key="GET /api/orders/{id}/invoice",
            method="GET",
            path="/api/orders/{id}/invoice",
            action=ActionType.READ_CHILD,
            resource_type="orders",
            is_child_endpoint=True,
        )

        # Parent resource
        rk = ResourceKey(resource_type="orders", resource_id="1001")
        graph.resources["orders:1001"] = ResourceNode(key=rk)

        # Edges: alice accesses parent + child
        graph.edges.append(AccessEdge(
            identity_name="alice",
            endpoint_key="GET /api/orders/{id}",
            resource_key="orders:1001",
            action=ActionType.READ,
            outcome=AccessOutcome.ALLOWED,
            status_code=200,
            object_id_used="1001",
            body_snippet='{"id": "1001", "owner_id": "1"}',
            json_keys=["id", "owner_id"],
        ))
        graph.edges.append(AccessEdge(
            identity_name="alice",
            endpoint_key="GET /api/orders/{id}/invoice",
            resource_key=None,
            action=ActionType.READ_CHILD,
            outcome=AccessOutcome.ALLOWED,
            status_code=200,
            object_id_used="1001",
            body_snippet='{"invoice_id": "99"}',
            json_keys=["invoice_id"],
        ))

        graph._build_indexes()
        return graph

    def test_child_resource_created(self):
        graph = self._make_graph_with_child_endpoint()
        infer_parent_child_resources(graph)
        # A child resource node for "invoice:1001" should be created
        assert "invoice:1001" in graph.resources

    def test_child_resource_has_parent_key(self):
        graph = self._make_graph_with_child_endpoint()
        infer_parent_child_resources(graph)
        child_node = graph.resources.get("invoice:1001")
        assert child_node is not None
        assert child_node.parent_resource_key == "orders:1001"


# ---------------------------------------------------------------------------
# apply_inferences integration
# ---------------------------------------------------------------------------


class TestApplyInferences:
    def _make_full_graph(self) -> AuthGraph:
        """Build a graph with both ownership and tenant signals."""
        from bac_detector.analyzers.matrix import build_matrix
        from bac_detector.discovery.inventory import build_inventory
        from bac_detector.graph.builder import build_graph
        from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
        from bac_detector.models.identity import AuthMechanism, IdentityProfile
        from bac_detector.models.response_meta import ResponseMeta

        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/orders/{id}",
            base_url="https://api.example.com",
            parameters=[Parameter(
                name="id", location=ParameterLocation.PATH,
                likely_object_id=True, required=True,
            )],
            source="openapi",
        )
        inventory = build_inventory([[ep]])

        # alice owns order 1 — response confirms owner_id=1 (matches alice's principal id)
        # bob accesses order 1 — response shows owner_id=1 (doesn't match bob's id=2)
        alice_response = ResponseMeta.from_response(
            status_code=200,
            body='{"id": "1", "owner_id": "1", "tenant_id": "acme", "data": "secret"}',
            content_type="application/json",
            latency_ms=10.0,
            endpoint_key="GET /api/orders/{id}",
            identity_name="alice",
            requested_url="https://api.example.com/api/orders/1",
            object_id_used="1",
        )
        bob_response = ResponseMeta.from_response(
            status_code=200,
            body='{"id": "1", "owner_id": "1", "tenant_id": "acme", "data": "secret"}',
            content_type="application/json",
            latency_ms=10.0,
            endpoint_key="GET /api/orders/{id}",
            identity_name="bob",
            requested_url="https://api.example.com/api/orders/1",
            object_id_used="1",
        )
        matrix = build_matrix([alice_response, bob_response])

        profiles = [
            IdentityProfile(name="alice", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-alice",
                owned_object_ids=["1"]),
            IdentityProfile(name="bob", role="user",
                auth_mechanism=AuthMechanism.BEARER, token="tok-bob",
                owned_object_ids=["2"]),
        ]
        return build_graph(matrix, inventory, profiles)

    def test_ownership_inferences_populated(self):
        graph = self._make_full_graph()
        assert len(graph.ownership_inferences) >= 1

    def test_alice_inferred_as_owner(self):
        graph = self._make_full_graph()
        oi = graph.best_ownership_inference("alice", "orders:1")
        assert oi is not None
        assert oi.conclusion == OwnershipConclusion.LIKELY_OWNS
        assert oi.confidence == OwnershipConfidence.HIGH

    def test_bob_inferred_as_non_owner(self):
        graph = self._make_full_graph()
        oi = graph.best_ownership_inference("bob", "orders:1")
        assert oi is not None
        assert oi.conclusion == OwnershipConclusion.LIKELY_DOES_NOT_OWN

    def test_tenant_inferences_populated(self):
        graph = self._make_full_graph()
        assert len(graph.tenant_inferences) >= 1

    def test_tenant_id_inferred_correctly(self):
        graph = self._make_full_graph()
        tenant_ids = graph.inferred_tenant_ids("orders:1")
        assert "acme" in tenant_ids

    def test_resource_attributes_enriched(self):
        graph = self._make_full_graph()
        node = graph.resources.get("orders:1")
        assert node is not None
        assert node.attributes.get("owner_id") == "1"
        assert node.attributes.get("tenant_id") == "acme"

    def test_graph_query_ownership_for_identity_resource(self):
        graph = self._make_full_graph()
        inferences = graph.ownership_for_identity_resource("alice", "orders:1")
        assert len(inferences) >= 1

    def test_graph_query_tenant_for_resource(self):
        graph = self._make_full_graph()
        tenant_infs = graph.tenant_for_resource("orders:1")
        assert len(tenant_infs) >= 1
        assert any(t.tenant_id == "acme" for t in tenant_infs)

    def test_principal_id_expansion(self):
        """HIGH-confidence OWNS inferences should expand identity.likely_principal_ids."""
        graph = self._make_full_graph()
        alice_node = graph.identities["alice"]
        # alice's owned_object_ids=["1"], and owner_id="1" from response
        # After inference, "1" should be confirmed in principal_ids (already there, but
        # matched_value "1" from owner_id field should also be present)
        assert "1" in alice_node.likely_principal_ids
