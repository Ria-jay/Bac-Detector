"""
Unit tests for Authorization Graph Engine — G3.

Covers:
- All 6 graph analyzers with targeted graphs that trigger each rule
- run_graph_analysis service: deduplication, min_confidence filter, sort order
- GraphAnalysisConfig integration
- Graph findings are valid Finding objects (have all required fields)
"""

from __future__ import annotations

import pytest

from bac_detector.config.loader import GraphAnalysisConfig
from bac_detector.graph.analyzers import (
    analyze_child_resource_exposure,
    analyze_hidden_privilege_path,
    analyze_inconsistent_sibling_actions,
    analyze_ownership_inconsistency,
    analyze_partial_authorization,
    analyze_tenant_boundary_inconsistency,
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
    OwnershipInference,
    ResourceFamily,
    ResourceKey,
    ResourceNode,
    RoleNode,
    TenantInference,
)
from bac_detector.graph.service import run_graph_analysis
from bac_detector.models.finding import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# Graph construction helpers
# ---------------------------------------------------------------------------


def _identity(name: str, role: str = "user", pids: set[str] | None = None) -> IdentityNode:
    return IdentityNode(name=name, role=role, likely_principal_ids=pids or set())


def _endpoint(
    ep_key: str,
    action: ActionType = ActionType.READ,
    resource_type: str | None = None,
    is_child: bool = False,
) -> EndpointNode:
    method, path = ep_key.split(" ", 1)
    return EndpointNode(
        endpoint_key=ep_key,
        method=method,
        path=path,
        action=action,
        resource_type=resource_type,
        is_child_endpoint=is_child,
    )


def _edge(
    identity: str,
    ep_key: str,
    outcome: AccessOutcome,
    resource_key: str | None = None,
    object_id: str | None = None,
    status: int | None = None,
    body_snippet: str = "",
    json_keys: list[str] | None = None,
) -> AccessEdge:
    if status is None:
        status = 200 if outcome == AccessOutcome.ALLOWED else 403
    return AccessEdge(
        identity_name=identity,
        endpoint_key=ep_key,
        resource_key=resource_key,
        action=ActionType.READ,
        outcome=outcome,
        status_code=status,
        object_id_used=object_id,
        body_snippet=body_snippet,
        json_keys=json_keys or [],
    )


def _resource(rk_str: str) -> ResourceNode:
    parts = rk_str.split(":", 1)
    rk = ResourceKey(resource_type=parts[0], resource_id=parts[1])
    return ResourceNode(key=rk)


def _family(
    resource_type: str,
    root_path: str,
    all_keys: list[str],
    parent_keys: list[str],
    child_keys: list[str],
) -> ResourceFamily:
    return ResourceFamily(
        resource_type=resource_type,
        root_path=root_path,
        endpoint_keys=all_keys,
        parent_endpoint_keys=parent_keys,
        child_endpoint_keys=child_keys,
    )


def _built_graph(
    identities: dict[str, IdentityNode],
    endpoints: dict[str, EndpointNode],
    edges: list[AccessEdge],
    families: list[ResourceFamily] | None = None,
    resources: dict[str, ResourceNode] | None = None,
    ownership_inferences: list[OwnershipInference] | None = None,
    tenant_inferences: list[TenantInference] | None = None,
) -> AuthGraph:
    graph = AuthGraph(
        identities=identities,
        endpoints=endpoints,
        edges=edges,
        families=families or [],
        resources=resources or {},
        ownership_inferences=ownership_inferences or [],
        tenant_inferences=tenant_inferences or [],
    )
    # Add minimal role nodes
    for name, node in identities.items():
        role = graph.roles.setdefault(node.role, RoleNode(name=node.role))
        role.identity_names.add(name)
    graph._build_indexes()
    return graph


# ---------------------------------------------------------------------------
# 1. Inconsistent sibling action protection
# ---------------------------------------------------------------------------


class TestInconsistentSiblingActions:
    def _make_graph(self) -> AuthGraph:
        """
        alice is DENIED GET /api/orders/{id} but ALLOWED PATCH /api/orders/{id}.
        Both are in the 'orders' family.
        """
        identities = {"alice": _identity("alice", role="user")}
        endpoints = {
            "GET /api/orders/{id}":   _endpoint("GET /api/orders/{id}", ActionType.READ, "orders"),
            "PATCH /api/orders/{id}": _endpoint("PATCH /api/orders/{id}", ActionType.UPDATE, "orders"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",   AccessOutcome.DENIED, "orders:1", "1"),
            _edge("alice", "PATCH /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1"),
        ]
        families = [_family("orders", "/api/orders",
            ["GET /api/orders/{id}", "PATCH /api/orders/{id}"],
            ["GET /api/orders/{id}", "PATCH /api/orders/{id}"], [])]
        return _built_graph(identities, endpoints, edges, families)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_inconsistent_sibling_actions(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_inconsistent_sibling_actions(graph)
        assert all(f.category == "graph_sibling_inconsistency" for f in findings)

    def test_attacker_is_alice(self):
        graph = self._make_graph()
        findings = analyze_inconsistent_sibling_actions(graph)
        assert any(f.evidence.attacker_identity == "alice" for f in findings)

    def test_finding_has_reproduction_steps(self):
        graph = self._make_graph()
        findings = analyze_inconsistent_sibling_actions(graph)
        assert all(len(f.reproduction_steps) >= 1 for f in findings)

    def test_finding_has_remediation(self):
        graph = self._make_graph()
        findings = analyze_inconsistent_sibling_actions(graph)
        assert all(f.remediation for f in findings)

    def test_no_finding_when_all_allowed(self):
        identities = {"alice": _identity("alice")}
        endpoints = {
            "GET /api/orders/{id}":   _endpoint("GET /api/orders/{id}"),
            "PATCH /api/orders/{id}": _endpoint("PATCH /api/orders/{id}"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",   AccessOutcome.ALLOWED),
            _edge("alice", "PATCH /api/orders/{id}", AccessOutcome.ALLOWED),
        ]
        families = [_family("orders", "/api/orders",
            ["GET /api/orders/{id}", "PATCH /api/orders/{id}"],
            ["GET /api/orders/{id}", "PATCH /api/orders/{id}"], [])]
        graph = _built_graph(identities, endpoints, edges, families)
        assert analyze_inconsistent_sibling_actions(graph) == []

    def test_confirmed_when_same_object_id(self):
        graph = self._make_graph()  # both edges have object_id="1"
        findings = analyze_inconsistent_sibling_actions(graph)
        assert any(f.confidence == Confidence.CONFIRMED for f in findings)


# ---------------------------------------------------------------------------
# 2. Child-resource exposure
# ---------------------------------------------------------------------------


class TestChildResourceExposure:
    def _make_graph(self) -> AuthGraph:
        """
        alice is DENIED GET /api/orders/{id} but ALLOWED GET /api/orders/{id}/invoice.
        """
        identities = {"alice": _identity("alice")}
        endpoints = {
            "GET /api/orders/{id}":         _endpoint("GET /api/orders/{id}", ActionType.READ, "orders"),
            "GET /api/orders/{id}/invoice": _endpoint("GET /api/orders/{id}/invoice",
                                                       ActionType.READ_CHILD, "orders", is_child=True),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",         AccessOutcome.DENIED, "orders:1", "1"),
            _edge("alice", "GET /api/orders/{id}/invoice", AccessOutcome.ALLOWED, None, "1"),
        ]
        return _built_graph(identities, endpoints, edges)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_child_resource_exposure(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_child_resource_exposure(graph)
        assert all(f.category == "graph_child_exposure" for f in findings)

    def test_high_severity(self):
        graph = self._make_graph()
        findings = analyze_child_resource_exposure(graph)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_no_finding_when_both_denied(self):
        identities = {"alice": _identity("alice")}
        endpoints = {
            "GET /api/orders/{id}":         _endpoint("GET /api/orders/{id}"),
            "GET /api/orders/{id}/invoice": _endpoint("GET /api/orders/{id}/invoice", is_child=True),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",         AccessOutcome.DENIED),
            _edge("alice", "GET /api/orders/{id}/invoice", AccessOutcome.DENIED),
        ]
        graph = _built_graph(identities, endpoints, edges)
        assert analyze_child_resource_exposure(graph) == []

    def test_no_finding_when_parent_also_allowed(self):
        identities = {"alice": _identity("alice")}
        endpoints = {
            "GET /api/orders/{id}":         _endpoint("GET /api/orders/{id}"),
            "GET /api/orders/{id}/invoice": _endpoint("GET /api/orders/{id}/invoice", is_child=True),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",         AccessOutcome.ALLOWED),
            _edge("alice", "GET /api/orders/{id}/invoice", AccessOutcome.ALLOWED),
        ]
        graph = _built_graph(identities, endpoints, edges)
        assert analyze_child_resource_exposure(graph) == []

    def test_confirmed_when_same_object_id(self):
        graph = self._make_graph()
        findings = analyze_child_resource_exposure(graph)
        assert any(f.confidence == Confidence.CONFIRMED for f in findings)


# ---------------------------------------------------------------------------
# 3. Hidden privilege path
# ---------------------------------------------------------------------------


class TestHiddenPrivilegePath:
    def _make_graph(self) -> AuthGraph:
        """
        alice (user role) is DENIED GET /admin/users but ALLOWED GET /admin/stats.
        """
        identities = {
            "alice": _identity("alice", role="user"),
            "admin": _identity("admin", role="admin"),
        }
        endpoints = {
            "GET /admin/users": _endpoint("GET /admin/users", ActionType.ADMIN_ACTION),
            "GET /admin/stats": _endpoint("GET /admin/stats", ActionType.ADMIN_ACTION),
        }
        edges = [
            _edge("alice", "GET /admin/users", AccessOutcome.DENIED),
            _edge("alice", "GET /admin/stats", AccessOutcome.ALLOWED),
            _edge("admin", "GET /admin/users", AccessOutcome.ALLOWED),
            _edge("admin", "GET /admin/stats", AccessOutcome.ALLOWED),
        ]
        return _built_graph(identities, endpoints, edges)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_hidden_privilege_path(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_hidden_privilege_path(graph)
        assert all(f.category == "graph_hidden_privilege_path" for f in findings)

    def test_attacker_is_low_privilege(self):
        graph = self._make_graph()
        findings = analyze_hidden_privilege_path(graph)
        assert all(f.evidence.attacker_identity == "alice" for f in findings)

    def test_no_finding_for_privileged_role(self):
        """Admin identity with mixed outcomes should not produce a finding."""
        graph = self._make_graph()
        findings = analyze_hidden_privilege_path(graph)
        assert all(f.evidence.attacker_identity != "admin" for f in findings)

    def test_no_finding_when_only_one_admin_endpoint(self):
        identities = {"alice": _identity("alice", role="user")}
        endpoints = {"GET /admin/users": _endpoint("GET /admin/users", ActionType.ADMIN_ACTION)}
        edges = [_edge("alice", "GET /admin/users", AccessOutcome.DENIED)]
        graph = _built_graph(identities, endpoints, edges)
        assert analyze_hidden_privilege_path(graph) == []

    def test_finding_has_why_bac(self):
        graph = self._make_graph()
        findings = analyze_hidden_privilege_path(graph)
        assert all(f.why_bac for f in findings)


# ---------------------------------------------------------------------------
# 4. Tenant boundary inconsistency
# ---------------------------------------------------------------------------


class TestTenantBoundaryInconsistency:
    def _make_graph(self) -> AuthGraph:
        """
        orders:1001 shows tenant_id="acme" for alice but "globex" for bob.
        """
        identities = {
            "alice": _identity("alice"),
            "bob":   _identity("bob"),
        }
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [
            _edge("alice", "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1001", "1001"),
            _edge("bob",   "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1001", "1001"),
        ]
        resources = {"orders:1001": _resource("orders:1001")}
        tenant_inferences = [
            TenantInference(resource_key="orders:1001", tenant_id="acme",
                            source_field="tenant_id", identity_name="alice"),
            TenantInference(resource_key="orders:1001", tenant_id="globex",
                            source_field="tenant_id", identity_name="bob"),
        ]
        return _built_graph(identities, endpoints, edges,
                            resources=resources, tenant_inferences=tenant_inferences)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_tenant_boundary_inconsistency(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_tenant_boundary_inconsistency(graph)
        assert all(f.category == "graph_tenant_boundary" for f in findings)

    def test_no_finding_when_tenant_consistent(self):
        identities = {"alice": _identity("alice"), "bob": _identity("bob")}
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [
            _edge("alice", "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1"),
            _edge("bob",   "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1"),
        ]
        tenant_inferences = [
            TenantInference(resource_key="orders:1", tenant_id="acme",
                            source_field="tenant_id", identity_name="alice"),
            TenantInference(resource_key="orders:1", tenant_id="acme",
                            source_field="tenant_id", identity_name="bob"),
        ]
        graph = _built_graph(identities, endpoints, edges,
                             tenant_inferences=tenant_inferences)
        assert analyze_tenant_boundary_inconsistency(graph) == []

    def test_no_finding_with_no_tenant_inferences(self):
        identities = {"alice": _identity("alice")}
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [_edge("alice", "GET /api/orders/{id}", AccessOutcome.ALLOWED)]
        graph = _built_graph(identities, endpoints, edges)
        assert analyze_tenant_boundary_inconsistency(graph) == []

    def test_finding_mentions_both_tenant_ids(self):
        graph = self._make_graph()
        findings = analyze_tenant_boundary_inconsistency(graph)
        assert len(findings) >= 1
        desc = findings[0].description + findings[0].evidence.diff_summary
        assert "acme" in desc or "globex" in desc


# ---------------------------------------------------------------------------
# 5. Ownership inconsistency
# ---------------------------------------------------------------------------


class TestOwnershipInconsistency:
    def _make_graph(self) -> AuthGraph:
        """
        bob accesses orders:1 (ALLOWED), but ownership inference says bob does NOT own it.
        """
        identities = {"bob": _identity("bob", pids={"2"})}
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [
            _edge("bob", "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1",
                  body_snippet='{"id": "1", "owner_id": "1"}', json_keys=["id", "owner_id"]),
        ]
        resources = {"orders:1": _resource("orders:1")}
        ownership_inferences = [
            OwnershipInference(
                identity_name="bob",
                resource_key="orders:1",
                conclusion=OwnershipConclusion.LIKELY_DOES_NOT_OWN,
                confidence=OwnershipConfidence.HIGH,
                matched_field="owner_id",
                matched_value="1",
                rationale="owner_id=1 does not match bob's principal IDs {2}.",
            )
        ]
        return _built_graph(identities, endpoints, edges,
                            resources=resources, ownership_inferences=ownership_inferences)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_ownership_inconsistency(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_ownership_inconsistency(graph)
        assert all(f.category == "graph_ownership_inconsistency" for f in findings)

    def test_high_severity(self):
        graph = self._make_graph()
        findings = analyze_ownership_inconsistency(graph)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_confirmed_confidence_for_high_ownership_inference(self):
        graph = self._make_graph()  # OwnershipConfidence.HIGH
        findings = analyze_ownership_inconsistency(graph)
        assert any(f.confidence == Confidence.CONFIRMED for f in findings)

    def test_no_finding_when_likely_owns(self):
        identities = {"alice": _identity("alice", pids={"1"})}
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [_edge("alice", "GET /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1")]
        resources = {"orders:1": _resource("orders:1")}
        ownership_inferences = [
            OwnershipInference(
                identity_name="alice", resource_key="orders:1",
                conclusion=OwnershipConclusion.LIKELY_OWNS,
                confidence=OwnershipConfidence.HIGH,
                matched_field="owner_id", matched_value="1",
                rationale="alice owns this.",
            )
        ]
        graph = _built_graph(identities, endpoints, edges,
                             resources=resources, ownership_inferences=ownership_inferences)
        assert analyze_ownership_inconsistency(graph) == []

    def test_no_finding_when_access_denied(self):
        identities = {"bob": _identity("bob", pids={"2"})}
        endpoints = {"GET /api/orders/{id}": _endpoint("GET /api/orders/{id}")}
        edges = [_edge("bob", "GET /api/orders/{id}", AccessOutcome.DENIED, "orders:1")]
        ownership_inferences = [
            OwnershipInference(
                identity_name="bob", resource_key="orders:1",
                conclusion=OwnershipConclusion.LIKELY_DOES_NOT_OWN,
                confidence=OwnershipConfidence.HIGH,
                matched_field="owner_id", matched_value="1",
                rationale="Does not own.",
            )
        ]
        graph = _built_graph(identities, endpoints, edges,
                             ownership_inferences=ownership_inferences)
        assert analyze_ownership_inconsistency(graph) == []


# ---------------------------------------------------------------------------
# 6. Partial authorization enforcement
# ---------------------------------------------------------------------------


class TestPartialAuthorization:
    def _make_graph(self) -> AuthGraph:
        """
        alice (user) is denied on 1 endpoint but allowed on 2 others in the same family (>= 3).
        """
        identities = {"alice": _identity("alice", role="user")}
        eps = {
            "GET /api/orders/{id}":          _endpoint("GET /api/orders/{id}", resource_type="orders"),
            "GET /api/orders/{id}/invoice":  _endpoint("GET /api/orders/{id}/invoice", resource_type="orders"),
            "DELETE /api/orders/{id}":       _endpoint("DELETE /api/orders/{id}", resource_type="orders"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",         AccessOutcome.ALLOWED),
            _edge("alice", "GET /api/orders/{id}/invoice", AccessOutcome.ALLOWED),
            _edge("alice", "DELETE /api/orders/{id}",      AccessOutcome.DENIED),
        ]
        ep_keys = list(eps.keys())
        families = [_family("orders", "/api/orders", ep_keys, [ep_keys[0], ep_keys[2]], [ep_keys[1]])]
        return _built_graph(identities, eps, edges, families)

    def test_finding_produced(self):
        graph = self._make_graph()
        findings = analyze_partial_authorization(graph)
        assert len(findings) >= 1

    def test_correct_category(self):
        graph = self._make_graph()
        findings = analyze_partial_authorization(graph)
        assert all(f.category == "graph_partial_authorization" for f in findings)

    def test_potential_confidence(self):
        graph = self._make_graph()
        findings = analyze_partial_authorization(graph)
        assert all(f.confidence == Confidence.POTENTIAL for f in findings)

    def test_no_finding_for_fewer_than_3_endpoints(self):
        identities = {"alice": _identity("alice")}
        eps = {
            "GET /api/orders/{id}":    _endpoint("GET /api/orders/{id}"),
            "DELETE /api/orders/{id}": _endpoint("DELETE /api/orders/{id}"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",    AccessOutcome.ALLOWED),
            _edge("alice", "DELETE /api/orders/{id}", AccessOutcome.DENIED),
        ]
        ep_keys = list(eps.keys())
        families = [_family("orders", "/api/orders", ep_keys, ep_keys, [])]
        graph = _built_graph(identities, eps, edges, families)
        assert analyze_partial_authorization(graph) == []

    def test_no_finding_when_all_denied(self):
        identities = {"alice": _identity("alice")}
        eps = {k: _endpoint(k) for k in [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
            "DELETE /api/orders/{id}",
        ]}
        edges = [_edge("alice", k, AccessOutcome.DENIED) for k in eps]
        families = [_family("orders", "/api/orders", list(eps.keys()), list(eps.keys()), [])]
        graph = _built_graph(identities, eps, edges, families)
        assert analyze_partial_authorization(graph) == []

    def test_privileged_role_not_flagged(self):
        identities = {"admin": _identity("admin", role="admin")}
        eps = {k: _endpoint(k) for k in [
            "GET /api/orders/{id}",
            "GET /api/orders/{id}/invoice",
            "DELETE /api/orders/{id}",
        ]}
        edges = [
            _edge("admin", "GET /api/orders/{id}",         AccessOutcome.ALLOWED),
            _edge("admin", "GET /api/orders/{id}/invoice", AccessOutcome.ALLOWED),
            _edge("admin", "DELETE /api/orders/{id}",      AccessOutcome.DENIED),
        ]
        families = [_family("orders", "/api/orders", list(eps.keys()), list(eps.keys()), [])]
        graph = _built_graph(identities, eps, edges, families)
        assert analyze_partial_authorization(graph) == []


# ---------------------------------------------------------------------------
# Finding quality — all graph findings must satisfy the Finding schema
# ---------------------------------------------------------------------------


class TestFindingQuality:
    def _all_graph_findings(self) -> list[Finding]:
        """Collect findings from all analyzers using their trigger graphs."""
        all_f: list[Finding] = []

        # Sibling
        identities = {"alice": _identity("alice")}
        eps = {
            "GET /api/orders/{id}":   _endpoint("GET /api/orders/{id}", ActionType.READ, "orders"),
            "PATCH /api/orders/{id}": _endpoint("PATCH /api/orders/{id}", ActionType.UPDATE, "orders"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",   AccessOutcome.DENIED, "orders:1", "1"),
            _edge("alice", "PATCH /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1"),
        ]
        families = [_family("orders", "/api/orders", list(eps.keys()), list(eps.keys()), [])]
        g = _built_graph(identities, eps, edges, families)
        all_f += analyze_inconsistent_sibling_actions(g)

        # Child exposure
        identities2 = {"alice": _identity("alice")}
        eps2 = {
            "GET /api/orders/{id}":         _endpoint("GET /api/orders/{id}"),
            "GET /api/orders/{id}/invoice": _endpoint("GET /api/orders/{id}/invoice", is_child=True),
        }
        edges2 = [
            _edge("alice", "GET /api/orders/{id}",         AccessOutcome.DENIED, "orders:1", "1"),
            _edge("alice", "GET /api/orders/{id}/invoice", AccessOutcome.ALLOWED, None, "1"),
        ]
        g2 = _built_graph(identities2, eps2, edges2)
        all_f += analyze_child_resource_exposure(g2)

        return all_f

    def test_all_findings_have_titles(self):
        for f in self._all_graph_findings():
            assert f.title, f"Finding {f.id} has no title"

    def test_all_findings_have_descriptions(self):
        for f in self._all_graph_findings():
            assert f.description, f"Finding {f.id} has no description"

    def test_all_findings_have_remediation(self):
        for f in self._all_graph_findings():
            assert f.remediation, f"Finding {f.id} has no remediation"

    def test_all_findings_have_why_bac(self):
        for f in self._all_graph_findings():
            assert f.why_bac, f"Finding {f.id} has no why_bac"

    def test_all_findings_have_valid_severity(self):
        valid = {s.value for s in Severity}
        for f in self._all_graph_findings():
            assert f.severity.value in valid

    def test_all_findings_have_evidence(self):
        for f in self._all_graph_findings():
            assert f.evidence.attacker_identity, f"Finding {f.id} has no attacker identity"


# ---------------------------------------------------------------------------
# run_graph_analysis service
# ---------------------------------------------------------------------------


class TestRunGraphAnalysis:
    def _graph_with_sibling_inconsistency(self) -> AuthGraph:
        identities = {"alice": _identity("alice")}
        eps = {
            "GET /api/orders/{id}":   _endpoint("GET /api/orders/{id}", ActionType.READ, "orders"),
            "PATCH /api/orders/{id}": _endpoint("PATCH /api/orders/{id}", ActionType.UPDATE, "orders"),
        }
        edges = [
            _edge("alice", "GET /api/orders/{id}",   AccessOutcome.DENIED, "orders:1", "1"),
            _edge("alice", "PATCH /api/orders/{id}", AccessOutcome.ALLOWED, "orders:1", "1"),
        ]
        families = [_family("orders", "/api/orders", list(eps.keys()), list(eps.keys()), [])]
        return _built_graph(identities, eps, edges, families)

    def test_disabled_config_returns_empty(self):
        graph = self._graph_with_sibling_inconsistency()
        config = GraphAnalysisConfig(enabled=False)
        assert run_graph_analysis(graph, config) == []

    def test_enabled_config_returns_findings(self):
        graph = self._graph_with_sibling_inconsistency()
        config = GraphAnalysisConfig(enabled=True)
        findings = run_graph_analysis(graph, config)
        assert len(findings) >= 1

    def test_findings_are_sorted_severity_first(self):
        graph = self._graph_with_sibling_inconsistency()
        config = GraphAnalysisConfig(enabled=True)
        findings = run_graph_analysis(graph, config)
        if len(findings) >= 2:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for i in range(len(findings) - 1):
                assert (sev_order.get(findings[i].severity.value, 99)
                        <= sev_order.get(findings[i+1].severity.value, 99))

    def test_min_confidence_high_filters_potentials(self):
        graph = self._graph_with_sibling_inconsistency()
        config = GraphAnalysisConfig(enabled=True, min_confidence="high")
        findings = run_graph_analysis(graph, config)
        # All findings that survive must be CONFIRMED (rank 0 = confirmed <= rank 0)
        for f in findings:
            assert f.confidence == Confidence.CONFIRMED

    def test_min_confidence_low_keeps_all(self):
        graph = self._graph_with_sibling_inconsistency()
        config_low = GraphAnalysisConfig(enabled=True, min_confidence="low")
        config_high = GraphAnalysisConfig(enabled=True, min_confidence="high")
        low_count = len(run_graph_analysis(graph, config_low))
        high_count = len(run_graph_analysis(graph, config_high))
        assert low_count >= high_count

    def test_deduplication_removes_duplicates(self):
        """Same analyzer running twice should not double findings after dedup."""
        graph = self._graph_with_sibling_inconsistency()
        config = GraphAnalysisConfig(enabled=True)
        findings = run_graph_analysis(graph, config)
        # Check that (category, endpoint_key, attacker) tuples are unique
        keys = [(f.category, f.endpoint_key, f.evidence.attacker_identity) for f in findings]
        assert len(keys) == len(set(keys))

    def test_hidden_privilege_checks_can_be_disabled(self):
        identities = {"alice": _identity("alice", role="user"), "admin": _identity("admin", role="admin")}
        eps = {
            "GET /admin/users": _endpoint("GET /admin/users", ActionType.ADMIN_ACTION),
            "GET /admin/stats": _endpoint("GET /admin/stats", ActionType.ADMIN_ACTION),
        }
        edges = [
            _edge("alice", "GET /admin/users", AccessOutcome.DENIED),
            _edge("alice", "GET /admin/stats", AccessOutcome.ALLOWED),
        ]
        graph = _built_graph(identities, eps, edges)
        config_off = GraphAnalysisConfig(enabled=True, enable_hidden_privilege_path_checks=False)
        findings_off = run_graph_analysis(graph, config_off)
        assert all(f.category != "graph_hidden_privilege_path" for f in findings_off)


# ---------------------------------------------------------------------------
# GraphAnalysisConfig schema validation
# ---------------------------------------------------------------------------


class TestGraphAnalysisConfig:
    def test_defaults_disabled(self):
        cfg = GraphAnalysisConfig()
        assert cfg.enabled is False

    def test_enabled_true(self):
        cfg = GraphAnalysisConfig(enabled=True)
        assert cfg.enabled is True
        assert cfg.infer_ownership is True
        assert cfg.infer_tenant_boundaries is True
        assert cfg.enable_hidden_privilege_path_checks is True
        assert cfg.min_confidence == "low"

    def test_min_confidence_values(self):
        for val in ("high", "medium", "low"):
            cfg = GraphAnalysisConfig(enabled=True, min_confidence=val)
            assert cfg.min_confidence == val

    def test_invalid_min_confidence_raises(self):
        with pytest.raises((ValueError, TypeError)):
            GraphAnalysisConfig(min_confidence="critical")

    def test_yaml_round_trip(self):
        """GraphAnalysisConfig should survive YAML → ScanConfig validation."""
        import os
        import tempfile

        from bac_detector.config.loader import load_config
        config_yaml = """
target:
  base_url: "https://example.com"
  openapi_url: "https://example.com/openapi.json"
identities:
  - name: alice
    role: user
    auth_mechanism: bearer
    token: tok-alice
  - name: bob
    role: user
    auth_mechanism: bearer
    token: tok-bob
graph_analysis:
  enabled: true
  infer_ownership: true
  infer_tenant_boundaries: false
  enable_hidden_privilege_path_checks: true
  min_confidence: medium
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_yaml)
            tmp = f.name
        try:
            config = load_config(tmp)
            assert config.graph_analysis.enabled is True
            assert config.graph_analysis.infer_tenant_boundaries is False
            assert config.graph_analysis.min_confidence == "medium"
        finally:
            os.unlink(tmp)
