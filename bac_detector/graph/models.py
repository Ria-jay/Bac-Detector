"""
Authorization Graph — data models.

All types are plain Python dataclasses (no pydantic, no external graph libs).
The graph is stored as an in-memory object with dict-based indexes for O(1)
lookup. Edges are stored as typed dataclasses, not generic tuples, so the
analyzer code stays readable.

Node types
----------
IdentityNode  — a configured test identity (alice, bob, admin)
RoleNode      — a role label (user, admin, guest, ...)
ResourceNode  — a normalized resource instance (order:1001, user:42)
EndpointNode  — a discovered API endpoint (GET /orders/{id})
ActionNode    — an inferred action type (read, list, update, delete, ...)

Edge types
----------
AccessEdge    — records one identity's access attempt at one resource via one endpoint.
                Carries the outcome (allowed/denied/error) and the raw ResponseMeta key.

Inference types (G2)
--------------------
OwnershipInference — conclusion about whether an identity owns a resource
TenantInference    — conclusion about the tenant scope of a resource

The graph also maintains secondary indexes for efficient lookup by identity,
resource, endpoint, and outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    """
    Inferred action type from HTTP method and path pattern.

    These are heuristic — the inference is documented and explainable
    even when imperfect.
    """
    READ          = "read"           # GET /resources/{id}
    LIST          = "list"           # GET /resources
    CREATE        = "create"         # POST /resources
    UPDATE        = "update"         # PUT or PATCH /resources/{id}
    DELETE        = "delete"         # DELETE /resources/{id}
    READ_CHILD    = "read_child"     # GET /resources/{id}/child
    CREATE_CHILD  = "create_child"   # POST /resources/{id}/child
    ADMIN_ACTION  = "admin_action"   # anything under /admin/
    CUSTOM_ACTION = "custom_action"  # POST /resources/{id}/refund etc.
    UNKNOWN       = "unknown"


class AccessOutcome(str, Enum):
    """The observed HTTP outcome of an access attempt."""
    ALLOWED = "allowed"   # 2xx
    DENIED  = "denied"    # 401 / 403
    ERROR   = "error"     # 5xx or network error
    UNKNOWN = "unknown"   # status=0 or dry-run


class OwnershipConfidence(str, Enum):
    """How confident we are about an ownership inference."""
    HIGH   = "high"    # field name exactly matches a primary ownership hint
    MEDIUM = "medium"  # indirect match via a secondary ownership hint
    LOW    = "low"     # heuristic guess with weak evidence


class OwnershipConclusion(str, Enum):
    """
    The conclusion of an ownership inference.

    LIKELY_OWNS           — evidence suggests the identity owns the resource
    LIKELY_DOES_NOT_OWN  — evidence suggests the identity does NOT own the resource
    UNKNOWN               — insufficient evidence to conclude either way
    """
    LIKELY_OWNS          = "likely_owns"
    LIKELY_DOES_NOT_OWN  = "likely_does_not_own"
    UNKNOWN              = "unknown"


# ---------------------------------------------------------------------------
# Resource key — canonical identifier for a resource instance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceKey:
    """
    Canonical identifier for a resource instance.

    Examples:
        ResourceKey("orders", "1001")         → "orders:1001"
        ResourceKey("users", "42")            → "users:42"
        ResourceKey("invoices", "99",
                    parent_key="orders:1001") → child of orders:1001
    """
    resource_type: str         # e.g. "orders", "users", "invoices"
    resource_id:   str         # e.g. "1001", "42"
    parent_key: Optional[str] = None    # "orders:1001" if this is a child resource
    tenant_id:  Optional[str] = None    # tenant scope, if inferrable

    @property
    def key(self) -> str:
        return f"{self.resource_type}:{self.resource_id}"

    def __str__(self) -> str:
        return self.key


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


@dataclass
class IdentityNode:
    """Represents a configured test identity."""
    name: str           # "alice"
    role: str           # "user"
    # Principal IDs this identity likely maps to (configured via owned_object_ids,
    # or expanded by G2 ownership inference from response bodies)
    likely_principal_ids: set[str] = field(default_factory=set)


@dataclass
class RoleNode:
    """Represents a role label."""
    name: str                           # "admin", "user", "guest"
    identity_names: set[str] = field(default_factory=set)


@dataclass
class ResourceNode:
    """
    Represents a normalized resource instance.

    Carries the canonical ResourceKey plus any attributes extracted from
    response bodies (e.g. owner_id, tenant_id seen in JSON).

    The attributes dict is populated during G2 inference. Keys are field names
    as they appear in the response body (e.g. "owner_id", "tenant_id").
    Values are the string representations of those field values.
    """
    key: ResourceKey
    # Attributes extracted from response JSON — populated during G2 inference
    # e.g. {"owner_id": "22", "tenant_id": "acme", "user_id": "15"}
    attributes: dict[str, str] = field(default_factory=dict)
    # Key of parent resource if this is a child resource (e.g. invoices:99 → orders:1001)
    parent_resource_key: Optional[str] = None

    @property
    def resource_type(self) -> str:
        return self.key.resource_type

    @property
    def resource_id(self) -> str:
        return self.key.resource_id


@dataclass
class EndpointNode:
    """Represents a discovered API endpoint."""
    endpoint_key: str    # "GET /api/orders/{id}"
    method:       str    # "GET"
    path:         str    # "/api/orders/{id}"
    action:       ActionType = ActionType.UNKNOWN
    # The resource type this endpoint acts on (inferred from path)
    resource_type: Optional[str] = None
    # True if the path contains a resource-family parent prefix
    is_child_endpoint: bool = False


@dataclass
class ActionNode:
    """Represents a named action type (mostly used for grouping / reporting)."""
    action_type: ActionType
    endpoint_keys: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------


@dataclass
class AccessEdge:
    """
    Records one identity's access attempt at one resource via one endpoint.

    This is the primary edge in the graph — everything else (resource families,
    sibling comparisons, ownership inference) is derived from these.
    """
    identity_name:  str
    endpoint_key:   str
    resource_key:   Optional[str]   # "orders:1001" or None if no object_id
    action:         ActionType
    outcome:        AccessOutcome
    status_code:    int
    object_id_used: Optional[str]   # raw object_id from the request
    # Snapshot fields from the ResponseMeta (no circular import)
    body_snippet:   str = ""
    json_keys:      list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Resource family
# ---------------------------------------------------------------------------


@dataclass
class ResourceFamily:
    """
    A group of related endpoints that act on the same conceptual resource type.

    Grouping is based on shared path prefix and resource type name.
    Example: /api/orders/{id}, /api/orders/{id}/invoice, /api/orders/{id}/refund
    all belong to the "orders" family.
    """
    resource_type: str              # "orders", "users"
    root_path:     str              # "/api/orders"
    endpoint_keys: list[str] = field(default_factory=list)
    # Which of these is the "parent" (no sub-resource suffix)
    parent_endpoint_keys: list[str] = field(default_factory=list)
    # Which are children / sub-resources
    child_endpoint_keys: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# G2: Inference result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OwnershipInference:
    """
    The result of inferring whether an identity owns a given resource.

    Produced by the G2 ownership inference pass. Each instance captures:
    - which identity and resource are involved
    - the conclusion (owns / does not own / unknown)
    - the confidence level
    - the field(s) that drove the inference and the evidence string

    Rationale field explains the inference in plain English, suitable for
    inclusion in analyzer finding descriptions.
    """
    identity_name:    str
    resource_key:     str           # "orders:1001"
    conclusion:       OwnershipConclusion
    confidence:       OwnershipConfidence
    # The response body field that triggered this inference (e.g. "owner_id")
    matched_field:    Optional[str] = None
    # The value extracted from the response body for that field (e.g. "22")
    matched_value:    Optional[str] = None
    # Plain-English explanation of why this conclusion was reached
    rationale:        str = ""


@dataclass(frozen=True)
class TenantInference:
    """
    The result of inferring the tenant scope of a resource.

    Produced by the G2 tenant inference pass.  A resource has an inferred
    tenant_id when the response body contains a recognized tenant-scoping
    field (tenant_id, organization_id, org_id, etc.).

    When two identities access the same resource and the inferred tenant
    differs, that is a tenant boundary inconsistency signal for G3 analyzers.
    """
    resource_key:   str    # "orders:1001"
    tenant_id:      str    # the inferred tenant identifier
    source_field:   str    # which response field provided this (e.g. "tenant_id")
    identity_name:  str    # which identity's response was the source


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


@dataclass
class AuthGraph:
    """
    In-memory authorization graph.

    Stores nodes and edges with dict-based indexes for fast lookup.
    The graph is built once from replay results and then queried
    by the analyzers — it is read-only after construction.

    G1 fields: identities, roles, resources, endpoints, actions, edges, families
    G2 fields: ownership_inferences, tenant_inferences

    Primary lookup patterns supported:
        - All access edges for an identity
        - All access edges for a resource
        - All access edges for an endpoint
        - Edges by (identity, resource)
        - Edges by (identity, endpoint)
        - Ownership inferences by (identity, resource)
        - Tenant inferences by resource
    """

    # Nodes
    identities: dict[str, IdentityNode]         = field(default_factory=dict)
    roles:      dict[str, RoleNode]             = field(default_factory=dict)
    resources:  dict[str, ResourceNode]         = field(default_factory=dict)
    endpoints:  dict[str, EndpointNode]         = field(default_factory=dict)
    actions:    dict[ActionType, ActionNode]    = field(default_factory=dict)

    # Edges (all access attempts)
    edges: list[AccessEdge] = field(default_factory=list)

    # Resource families (grouped by path prefix)
    families: list[ResourceFamily] = field(default_factory=list)

    # G2: Inference results
    ownership_inferences: list[OwnershipInference] = field(default_factory=list)
    tenant_inferences:    list[TenantInference]    = field(default_factory=list)

    # ---------------------------------------------------------------------------
    # Indexes (built once after graph construction)
    # ---------------------------------------------------------------------------

    _idx_by_identity:           dict[str, list[AccessEdge]] = field(default_factory=dict, repr=False)
    _idx_by_resource:           dict[str, list[AccessEdge]] = field(default_factory=dict, repr=False)
    _idx_by_endpoint:           dict[str, list[AccessEdge]] = field(default_factory=dict, repr=False)
    _idx_by_identity_endpoint:  dict[tuple[str,str], list[AccessEdge]] = field(default_factory=dict, repr=False)
    _idx_by_identity_resource:  dict[tuple[str,str], list[AccessEdge]] = field(default_factory=dict, repr=False)
    # G2 inference indexes
    _idx_ownership_by_identity_resource: dict[tuple[str,str], list[OwnershipInference]] = field(default_factory=dict, repr=False)
    _idx_tenant_by_resource:             dict[str, list[TenantInference]]               = field(default_factory=dict, repr=False)
    _indexes_built: bool = field(default=False, repr=False)

    def _build_indexes(self) -> None:
        """Rebuild all lookup indexes from self.edges and inference results."""
        self._idx_by_identity.clear()
        self._idx_by_resource.clear()
        self._idx_by_endpoint.clear()
        self._idx_by_identity_endpoint.clear()
        self._idx_by_identity_resource.clear()
        self._idx_ownership_by_identity_resource.clear()
        self._idx_tenant_by_resource.clear()

        for edge in self.edges:
            self._idx_by_identity.setdefault(edge.identity_name, []).append(edge)
            self._idx_by_endpoint.setdefault(edge.endpoint_key, []).append(edge)
            if edge.resource_key:
                self._idx_by_resource.setdefault(edge.resource_key, []).append(edge)
                self._idx_by_identity_resource.setdefault(
                    (edge.identity_name, edge.resource_key), []
                ).append(edge)
            self._idx_by_identity_endpoint.setdefault(
                (edge.identity_name, edge.endpoint_key), []
            ).append(edge)

        for oi in self.ownership_inferences:
            self._idx_ownership_by_identity_resource.setdefault(
                (oi.identity_name, oi.resource_key), []
            ).append(oi)

        for ti in self.tenant_inferences:
            self._idx_tenant_by_resource.setdefault(ti.resource_key, []).append(ti)

        self._indexes_built = True

    def _ensure_indexes(self) -> None:
        if not self._indexes_built:
            self._build_indexes()

    # ---------------------------------------------------------------------------
    # Access edge query methods (G1)
    # ---------------------------------------------------------------------------

    def edges_for_identity(self, identity_name: str) -> list[AccessEdge]:
        """All access edges for a given identity."""
        self._ensure_indexes()
        return list(self._idx_by_identity.get(identity_name, []))

    def edges_for_endpoint(self, endpoint_key: str) -> list[AccessEdge]:
        """All access edges for a given endpoint."""
        self._ensure_indexes()
        return list(self._idx_by_endpoint.get(endpoint_key, []))

    def edges_for_resource(self, resource_key: str) -> list[AccessEdge]:
        """All access edges for a given resource key."""
        self._ensure_indexes()
        return list(self._idx_by_resource.get(resource_key, []))

    def edges_for_identity_endpoint(
        self, identity_name: str, endpoint_key: str
    ) -> list[AccessEdge]:
        """All edges for a specific (identity, endpoint) pair."""
        self._ensure_indexes()
        return list(self._idx_by_identity_endpoint.get((identity_name, endpoint_key), []))

    def edges_for_identity_resource(
        self, identity_name: str, resource_key: str
    ) -> list[AccessEdge]:
        """All edges for a specific (identity, resource) pair."""
        self._ensure_indexes()
        return list(self._idx_by_identity_resource.get((identity_name, resource_key), []))

    def outcome_for_identity_endpoint(
        self, identity_name: str, endpoint_key: str
    ) -> Optional[AccessOutcome]:
        """
        Return the first recorded outcome for an (identity, endpoint) pair.
        Returns None if no edge exists.
        """
        edges = self.edges_for_identity_endpoint(identity_name, endpoint_key)
        if not edges:
            return None
        return edges[0].outcome

    # ---------------------------------------------------------------------------
    # G2 inference query methods
    # ---------------------------------------------------------------------------

    def ownership_for_identity_resource(
        self, identity_name: str, resource_key: str
    ) -> list[OwnershipInference]:
        """All ownership inferences for a specific (identity, resource) pair."""
        self._ensure_indexes()
        return list(self._idx_ownership_by_identity_resource.get(
            (identity_name, resource_key), []
        ))

    def best_ownership_inference(
        self, identity_name: str, resource_key: str
    ) -> Optional[OwnershipInference]:
        """
        Return the highest-confidence ownership inference for an (identity, resource) pair.

        Confidence priority: HIGH > MEDIUM > LOW.
        Returns None if no inference exists.
        """
        inferences = self.ownership_for_identity_resource(identity_name, resource_key)
        if not inferences:
            return None
        rank = {OwnershipConfidence.HIGH: 0, OwnershipConfidence.MEDIUM: 1, OwnershipConfidence.LOW: 2}
        return min(inferences, key=lambda i: rank.get(i.confidence, 99))

    def tenant_for_resource(self, resource_key: str) -> list[TenantInference]:
        """All tenant inferences for a given resource."""
        self._ensure_indexes()
        return list(self._idx_tenant_by_resource.get(resource_key, []))

    def inferred_tenant_ids(self, resource_key: str) -> set[str]:
        """All distinct tenant IDs inferred for a resource (may be >1 if inconsistent)."""
        return {ti.tenant_id for ti in self.tenant_for_resource(resource_key)}

    # ---------------------------------------------------------------------------
    # Properties
    # ---------------------------------------------------------------------------

    @property
    def total_edges(self) -> int:
        return len(self.edges)

    @property
    def total_nodes(self) -> int:
        return (
            len(self.identities)
            + len(self.roles)
            + len(self.resources)
            + len(self.endpoints)
        )
