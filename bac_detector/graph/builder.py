"""
Authorization Graph — builder.

Constructs an AuthGraph from the existing Phase 3–4 pipeline outputs:
  - AuthMatrix  (all replay responses, indexed by endpoint/identity/object_id)
  - EndpointInventory  (discovered endpoints with parameter metadata)
  - list[IdentityProfile]  (configured test identities with roles)

The builder is the ONLY place that reads from those pipeline objects.
The rest of the graph module only sees AuthGraph.

Build steps
-----------
1. Create IdentityNode and RoleNode for every configured identity.
2. Create EndpointNode for every endpoint in the inventory, inferring
   action type from method + path.
3. Walk every cell in the AuthMatrix → create AccessEdge per response,
   normalizing the resource key and recording the outcome.
4. Create ResourceNode for every unique resource key encountered.
5. Group endpoints into ResourceFamily objects.
6. Build parent-child relationship map.
7. Finalize: build indexes on the graph.
"""

from __future__ import annotations

from bac_detector.analyzers.matrix import AuthMatrix
from bac_detector.discovery.inventory import EndpointInventory
from bac_detector.graph.inference import (
    apply_inferences,
    group_into_families,
    infer_action,
    infer_parent_child,
    normalize_resource,
)
from bac_detector.graph.models import (
    AccessEdge,
    AccessOutcome,
    ActionNode,
    AuthGraph,
    EndpointNode,
    IdentityNode,
    ResourceNode,
    RoleNode,
)
from bac_detector.models.identity import IdentityProfile
from bac_detector.models.response_meta import ResponseMeta
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


def build_graph(
    matrix: AuthMatrix,
    inventory: EndpointInventory,
    profiles: list[IdentityProfile],
) -> AuthGraph:
    """
    Build an AuthGraph from replay results and discovery data.

    This is the single entry point called by the graph service.
    The resulting graph is fully indexed and ready for analyzer queries.

    Args:
        matrix: The populated authorization matrix from Phase 3.
        inventory: The endpoint inventory from Phase 2.
        profiles: All configured identity profiles.

    Returns:
        Fully constructed and indexed AuthGraph.
    """
    graph = AuthGraph()

    # Step 1: identities and roles
    _add_identities(graph, profiles)

    # Step 2: endpoint nodes
    _add_endpoints(graph, inventory)

    # Step 3: access edges from matrix
    _add_access_edges(graph, matrix)

    # Step 4: resource nodes (collected from edges)
    _add_resource_nodes(graph)

    # Step 5: resource families
    ep_keys = list(graph.endpoints.keys())
    graph.families = group_into_families(ep_keys)

    # Step 6: mark child endpoints
    parent_child = infer_parent_child(ep_keys)
    for child_ep, _ in parent_child.items():
        if child_ep in graph.endpoints:
            graph.endpoints[child_ep].is_child_endpoint = True

    # Step 7: build indexes so G2 inference can use query methods
    graph._build_indexes()

    # Step 8: G2 inference — ownership, tenant, parent-child resource linking
    apply_inferences(graph)

    log.info(
        "graph_built",
        identities=len(graph.identities),
        endpoints=len(graph.endpoints),
        resources=len(graph.resources),
        edges=graph.total_edges,
        families=len(graph.families),
        ownership_inferences=len(graph.ownership_inferences),
        tenant_inferences=len(graph.tenant_inferences),
    )

    return graph


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def _add_identities(graph: AuthGraph, profiles: list[IdentityProfile]) -> None:
    """Add IdentityNode and RoleNode for each configured identity."""
    for profile in profiles:
        identity = IdentityNode(
            name=profile.name,
            role=profile.role,
            likely_principal_ids=set(profile.owned_object_ids),
        )
        graph.identities[profile.name] = identity

        role = graph.roles.setdefault(profile.role, RoleNode(name=profile.role))
        role.identity_names.add(profile.name)


def _add_endpoints(graph: AuthGraph, inventory: EndpointInventory) -> None:
    """Add EndpointNode for each endpoint in the inventory."""
    for ep in inventory.endpoints:
        action = infer_action(ep.method.value, ep.path)

        # Infer which resource type this endpoint acts on
        from bac_detector.graph.inference import _infer_resource_type
        resource_type = _infer_resource_type(ep.path)

        node = EndpointNode(
            endpoint_key=ep.endpoint_key,
            method=ep.method.value,
            path=ep.path,
            action=action,
            resource_type=resource_type,
        )
        graph.endpoints[ep.endpoint_key] = node

        # Action nodes (for grouping)
        if action not in graph.actions:
            graph.actions[action] = ActionNode(action_type=action)
        graph.actions[action].endpoint_keys.add(ep.endpoint_key)


def _add_access_edges(graph: AuthGraph, matrix: AuthMatrix) -> None:
    """
    Walk every matrix cell and create an AccessEdge per ResponseMeta.

    The matrix stores: endpoint_key → identity_name → object_id → ResponseMeta.
    We iterate all cells and convert each ResponseMeta into an AccessEdge.
    """
    for ep_key in matrix.endpoint_keys:
        for identity_name in matrix.identities_for(ep_key):
            for meta in matrix.responses_for_identity(ep_key, identity_name):
                edge = _meta_to_edge(meta, ep_key, identity_name)
                graph.edges.append(edge)


def _meta_to_edge(
    meta: ResponseMeta,
    ep_key: str,
    identity_name: str,
) -> AccessEdge:
    """Convert a ResponseMeta cell into an AccessEdge."""
    outcome = _outcome_from_status(meta.status_code, meta.error)

    method, path = ep_key.split(" ", 1)
    action = infer_action(method, path)

    rk = normalize_resource(ep_key, meta.object_id_used)
    resource_key_str = rk.key if rk else None

    return AccessEdge(
        identity_name=identity_name,
        endpoint_key=ep_key,
        resource_key=resource_key_str,
        action=action,
        outcome=outcome,
        status_code=meta.status_code,
        object_id_used=meta.object_id_used,
        body_snippet=meta.body_snippet,
        json_keys=list(meta.json_keys),
    )


def _outcome_from_status(status_code: int, error: str | None) -> AccessOutcome:
    """Map a status code to an AccessOutcome."""
    if error and error != "dry_run":
        return AccessOutcome.ERROR
    if status_code == 0:
        return AccessOutcome.UNKNOWN
    if 200 <= status_code < 300:
        return AccessOutcome.ALLOWED
    if status_code in (401, 403):
        return AccessOutcome.DENIED
    if status_code >= 500:
        return AccessOutcome.ERROR
    # 4xx other than 401/403 — treat as denied for access-control purposes
    if 400 <= status_code < 500:
        return AccessOutcome.DENIED
    return AccessOutcome.UNKNOWN


def _add_resource_nodes(graph: AuthGraph) -> None:
    """Create ResourceNode for every unique resource key seen in edges."""
    for edge in graph.edges:
        if edge.resource_key and edge.resource_key not in graph.resources:
            # Parse resource_type and resource_id from the key string "type:id"
            parts = edge.resource_key.split(":", 1)
            if len(parts) == 2:
                from bac_detector.graph.models import ResourceKey
                rk = ResourceKey(
                    resource_type=parts[0],
                    resource_id=parts[1],
                )
                graph.resources[edge.resource_key] = ResourceNode(key=rk)
