"""
Authorization Graph Engine — G1 + G2 + G3.

Public API:

    build_graph(matrix, inventory, profiles)  -> AuthGraph
    run_graph_analysis(graph, config)         -> list[Finding]

    Graph types:
        AuthGraph, AccessEdge, AccessOutcome, ActionType
        IdentityNode, RoleNode, ResourceNode, EndpointNode, ActionNode
        ResourceKey, ResourceFamily

    G2 inference types:
        OwnershipInference, OwnershipConclusion, OwnershipConfidence
        TenantInference

    Inference functions:
        infer_action(method, path)                -> ActionType
        normalize_resource(endpoint_key, oid)     -> ResourceKey | None
        group_into_families(endpoint_keys)        -> list[ResourceFamily]
        infer_parent_child(endpoint_keys)         -> dict[str, str]
        apply_inferences(graph)                   -> None  (mutates graph)
        infer_ownership_for_edge(edge, pids)      -> OwnershipInference | None
        infer_tenant_for_edge(edge)               -> TenantInference | None

    G3 analyzers (called via run_graph_analysis, or individually):
        analyze_inconsistent_sibling_actions(graph)    -> list[Finding]
        analyze_child_resource_exposure(graph)         -> list[Finding]
        analyze_hidden_privilege_path(graph)           -> list[Finding]
        analyze_tenant_boundary_inconsistency(graph)   -> list[Finding]
        analyze_ownership_inconsistency(graph)         -> list[Finding]
        analyze_partial_authorization(graph)           -> list[Finding]
"""

from bac_detector.graph.analyzers import (
    analyze_child_resource_exposure,
    analyze_hidden_privilege_path,
    analyze_inconsistent_sibling_actions,
    analyze_ownership_inconsistency,
    analyze_partial_authorization,
    analyze_tenant_boundary_inconsistency,
)
from bac_detector.graph.builder import build_graph
from bac_detector.graph.inference import (
    apply_inferences,
    group_into_families,
    infer_action,
    infer_ownership_for_edge,
    infer_parent_child,
    infer_parent_child_resources,
    infer_tenant_for_edge,
    normalize_resource,
)
from bac_detector.graph.models import (
    AccessEdge,
    AccessOutcome,
    ActionNode,
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

__all__ = [
    # Builder
    "build_graph",
    # Service / orchestration
    "run_graph_analysis",
    # G3 analyzers
    "analyze_child_resource_exposure",
    "analyze_hidden_privilege_path",
    "analyze_inconsistent_sibling_actions",
    "analyze_ownership_inconsistency",
    "analyze_partial_authorization",
    "analyze_tenant_boundary_inconsistency",
    # Inference functions
    "apply_inferences",
    "group_into_families",
    "infer_action",
    "infer_ownership_for_edge",
    "infer_parent_child",
    "infer_parent_child_resources",
    "infer_tenant_for_edge",
    "normalize_resource",
    # Graph model
    "AccessEdge",
    "AccessOutcome",
    "ActionNode",
    "ActionType",
    "AuthGraph",
    "EndpointNode",
    "IdentityNode",
    "OwnershipConfidence",
    "OwnershipConclusion",
    "OwnershipInference",
    "ResourceFamily",
    "ResourceKey",
    "ResourceNode",
    "RoleNode",
    "TenantInference",
]
