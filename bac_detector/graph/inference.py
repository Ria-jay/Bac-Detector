"""
Authorization Graph — inference functions.

All functions here are:
- Pure where possible (no side effects except apply_inferences which mutates graph)
- Deterministic (same input → same output)
- Documented with the heuristic rationale

Five concerns are handled here:

G1 (from Phase G1):
  1. Action inference     — HTTP method + path → ActionType
  2. Resource normalization — endpoint_key + object_id → ResourceKey
  3. Family grouping      — list of endpoint_keys → list[ResourceFamily]
  4. Parent-child inference — identify which endpoints are sub-resources

G2 (this phase):
  5. apply_inferences(graph) — orchestrates all G2 inference passes:
       a. Ownership inference   — who likely owns which resource
       b. Tenant inference      — which tenant scope a resource belongs to
       c. Parent-child resource — link child resource nodes to their parents
"""

from __future__ import annotations

import json
import re
from typing import Optional

from bac_detector.graph.models import (
    AccessEdge,
    AccessOutcome,
    ActionType,
    AuthGraph,
    OwnershipConfidence,
    OwnershipConclusion,
    OwnershipInference,
    ResourceFamily,
    ResourceKey,
    TenantInference,
)


# ---------------------------------------------------------------------------
# 1. Action inference  (G1 — unchanged)
# ---------------------------------------------------------------------------

# Path segments that strongly signal an admin action regardless of method
_ADMIN_SEGMENTS = frozenset({"admin", "internal", "management", "superuser", "root", "system"})

# Suffixes that indicate a named custom action on a resource (not a sub-resource)
_CUSTOM_ACTION_SUFFIXES = frozenset({
    "refund", "cancel", "approve", "reject", "disable", "enable", "promote",
    "demote", "lock", "unlock", "archive", "restore", "publish", "unpublish",
    "verify", "resend", "revoke", "activate", "deactivate", "reset",
    "suspend", "unsuspend", "ban", "unban",
})


def infer_action(method: str, path: str) -> ActionType:
    """
    Infer the likely action type from an HTTP method and path template.

    Heuristic rules applied in order (first match wins):

    1. Any path containing an admin segment → ADMIN_ACTION
    2. Method+path combinations with a custom action suffix → CUSTOM_ACTION
    3. GET on a path with an object-id placeholder → READ
    4. GET on a path without an object-id placeholder → LIST
    5. POST on a path with a sub-resource (parent/{id}/child) → CREATE_CHILD
    6. GET on a path with a sub-resource (parent/{id}/child) → READ_CHILD
    7. POST → CREATE
    8. PUT or PATCH → UPDATE
    9. DELETE → DELETE
    10. Anything else → UNKNOWN
    """
    m = method.upper()
    p = path.lower().strip("/")
    segments = p.split("/")

    # Rule 1: admin path segment
    if _ADMIN_SEGMENTS & set(segments):
        return ActionType.ADMIN_ACTION

    # Rule 2: custom action suffix
    if len(segments) >= 2:
        last = segments[-1]
        if last in _CUSTOM_ACTION_SUFFIXES:
            return ActionType.CUSTOM_ACTION
        if len(segments) >= 3 and segments[-2] in _CUSTOM_ACTION_SUFFIXES:
            return ActionType.CUSTOM_ACTION

    has_id_placeholder = "{" in path

    # Rules 3 & 4: GET
    if m == "GET":
        if _is_child_path(segments):
            return ActionType.READ_CHILD
        if has_id_placeholder:
            return ActionType.READ
        return ActionType.LIST

    # Rule 5: POST on child path
    if m == "POST":
        if _is_child_path(segments):
            return ActionType.CREATE_CHILD
        return ActionType.CREATE

    # Rules 6–7
    if m in ("PUT", "PATCH"):
        return ActionType.UPDATE
    if m == "DELETE":
        return ActionType.DELETE

    return ActionType.UNKNOWN


def _is_child_path(segments: list[str]) -> bool:
    """
    Return True if the path looks like a child/sub-resource path.

    A child path has a brace-placeholder segment followed by at least one
    more non-placeholder, non-custom-action segment.
    """
    brace_found = False
    for seg in segments:
        if seg.startswith("{") and seg.endswith("}"):
            brace_found = True
        elif brace_found and seg not in _CUSTOM_ACTION_SUFFIXES:
            return True
    return False


# ---------------------------------------------------------------------------
# 2. Resource normalization  (G1 — unchanged)
# ---------------------------------------------------------------------------

_RESOURCE_TYPE_FROM_PATH_RE = re.compile(
    r"/(?P<type>[a-zA-Z][a-zA-Z0-9_-]*)/"
    r"\{[^}]+\}"
)


def normalize_resource(
    endpoint_key: str,
    object_id: Optional[str],
    *,
    parent_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[ResourceKey]:
    """
    Produce a canonical ResourceKey for a (endpoint, object_id) pair.

    Returns None if the endpoint has no object-id (list endpoints).
    """
    if object_id is None:
        return None

    _, path = endpoint_key.split(" ", 1)
    resource_type = _infer_resource_type(path)
    if resource_type is None:
        resource_type = _fallback_resource_type(path)
    if resource_type is None:
        return None

    return ResourceKey(
        resource_type=resource_type,
        resource_id=object_id,
        parent_key=parent_key,
        tenant_id=tenant_id,
    )


_VERSION_SEGMENT_RE = re.compile(r"^v\d+$", re.IGNORECASE)


def _infer_resource_type(path: str) -> Optional[str]:
    """
    Extract the resource type from the path segment immediately before the
    first object-id placeholder, skipping API version segments like v1, v2.

    Examples:
        /api/orders/{id}      → "orders"
        /api/v2/orders/{id}   → "orders"
        /api/v2/{id}          → None  (v2 is a version, not a resource type)
        /v1/{user_id}         → None  (let fallback handle)
    """
    for m in _RESOURCE_TYPE_FROM_PATH_RE.finditer(path):
        t = m.group("type").lower()
        if not _VERSION_SEGMENT_RE.match(t):
            return t
    return None


def _fallback_resource_type(path: str) -> Optional[str]:
    """Fallback: return the last non-placeholder, non-version path segment."""
    segments = path.strip("/").split("/")
    for seg in reversed(segments):
        if not seg.startswith("{") and not re.match(r"^v\d+$", seg):
            return seg.lower()
    return None


# ---------------------------------------------------------------------------
# 3. Resource family grouping  (G1 — unchanged)
# ---------------------------------------------------------------------------


def group_into_families(endpoint_keys: list[str]) -> list[ResourceFamily]:
    """
    Group a list of endpoint keys into resource families.

    Two endpoints belong to the same family if they share a common path
    prefix up to and including the first object-id placeholder segment.
    Only produces a family when ≥2 endpoints share a resource type.
    """
    families: dict[str, tuple[str, str, list[str]]] = {}

    for ep_key in endpoint_keys:
        _, path = ep_key.split(" ", 1)
        root_path, resource_type = _extract_family_root(path)
        if resource_type is None:
            continue
        if resource_type not in families:
            families[resource_type] = (resource_type, root_path, [])
        families[resource_type][2].append(ep_key)

    result: list[ResourceFamily] = []
    for resource_type, (rt, root_path, ep_keys) in families.items():
        parent_keys = []
        child_keys = []
        for ep_key in ep_keys:
            _, path = ep_key.split(" ", 1)
            if _is_parent_endpoint(path, root_path):
                parent_keys.append(ep_key)
            else:
                child_keys.append(ep_key)

        if len(ep_keys) >= 2:
            result.append(ResourceFamily(
                resource_type=resource_type,
                root_path=root_path,
                endpoint_keys=list(ep_keys),
                parent_endpoint_keys=parent_keys,
                child_endpoint_keys=child_keys,
            ))

    return result


def _extract_family_root(path: str) -> tuple[str, Optional[str]]:
    """Return (root_path, resource_type) for a path, or ("", None) if ungroupable."""
    segments = path.strip("/").split("/")
    prefix_segs: list[str] = []
    resource_type: Optional[str] = None

    for seg in segments:
        if seg.startswith("{"):
            if prefix_segs:
                resource_type = prefix_segs[-1].lower()
            break
        prefix_segs.append(seg)
    else:
        for seg in reversed(prefix_segs):
            if not re.match(r"^v\d+$", seg):
                resource_type = seg.lower()
                break

    root_path = "/" + "/".join(prefix_segs) if prefix_segs else "/"
    return root_path, resource_type


def _is_parent_endpoint(path: str, root_path: str) -> bool:
    """Return True if this endpoint is the parent of a family (no sub-path after placeholder)."""
    segments = path.strip("/").split("/")
    brace_found = False
    after_brace: list[str] = []
    for seg in segments:
        if seg.startswith("{"):
            brace_found = True
        elif brace_found:
            after_brace.append(seg)
    return len(after_brace) == 0


# ---------------------------------------------------------------------------
# 4. Parent-child inference  (G1 — unchanged)
# ---------------------------------------------------------------------------


def infer_parent_child(endpoint_keys: list[str]) -> dict[str, str]:
    """
    Infer parent → child relationships between endpoint keys.

    Returns a dict mapping child_endpoint_key → parent_endpoint_key.
    """
    result: dict[str, str] = {}

    parent_map: dict[str, str] = {}
    for ep_key in endpoint_keys:
        _, path = ep_key.split(" ", 1)
        canonical = _path_up_to_first_placeholder(path)
        if canonical and canonical not in parent_map:
            parent_map[canonical] = ep_key

    for ep_key in endpoint_keys:
        _, path = ep_key.split(" ", 1)
        if not _is_child_path(path.strip("/").split("/")):
            continue
        canonical = _path_up_to_first_placeholder(path)
        if canonical and canonical in parent_map:
            parent_ep = parent_map[canonical]
            if parent_ep != ep_key:
                result[ep_key] = parent_ep

    return result


def _path_up_to_first_placeholder(path: str) -> Optional[str]:
    """Return the path prefix including the first {placeholder} segment."""
    segments = path.strip("/").split("/")
    collected: list[str] = []
    for seg in segments:
        collected.append(seg)
        if seg.startswith("{"):
            return "/" + "/".join(collected)
    return None


# ---------------------------------------------------------------------------
# G2 — Ownership field catalog
# ---------------------------------------------------------------------------

# Fields whose presence in a response body provides strong evidence of ownership.
# The value in these fields should directly identify the owning principal.
#
# PRIMARY fields: the response field is explicitly an "owner" or "creator" of the resource.
# Confidence: HIGH when the value matches a known principal ID of the requesting identity.
_PRIMARY_OWNERSHIP_FIELDS: frozenset[str] = frozenset({
    "owner_id",
    "user_id",
    "created_by",
    "author_id",
    "submitter_id",
    "requester_id",
})

# SECONDARY fields: the response field identifies an associated entity that may own the resource.
# The relationship is less direct (e.g. account_id may map to user_id through a lookup).
# Confidence: MEDIUM when the value matches a known principal ID.
_SECONDARY_OWNERSHIP_FIELDS: frozenset[str] = frozenset({
    "account_id",
    "customer_id",
    "profile_id",
    "member_id",
    "assigned_to",
    "assigned_user_id",
    "contact_id",
})

# TENANT fields: identify the tenant scope of a resource, not direct ownership.
# Used for tenant inference, not ownership inference.
_TENANT_FIELDS: frozenset[str] = frozenset({
    "tenant_id",
    "organization_id",
    "org_id",
    "company_id",
    "workspace_id",
    "team_id",
    "group_id",
    "account_id",   # also a secondary ownership field — dual purpose
})

# All ownership-relevant fields (for quick json_keys membership check)
_ALL_OWNERSHIP_FIELDS: frozenset[str] = (
    _PRIMARY_OWNERSHIP_FIELDS | _SECONDARY_OWNERSHIP_FIELDS
)


# ---------------------------------------------------------------------------
# G2 — Body parsing helpers
# ---------------------------------------------------------------------------


def _extract_field_values(body_snippet: str, fields: frozenset[str]) -> dict[str, str]:
    """
    Extract values for specific fields from a response body snippet.

    Strategy:
    1. Try full JSON parse — works for complete, untruncated responses.
    2. Fall back to a targeted regex for each known field — handles truncation.

    The regex is conservative: it only matches simple string and integer values,
    not nested objects or arrays, to avoid false matches.

    Args:
        body_snippet: First 256 characters of the response body.
        fields: The set of field names to extract.

    Returns:
        Dict of field_name → string value for any fields found.
        Values are always strings (int values are converted).
    """
    if not body_snippet or not body_snippet.strip().startswith("{"):
        return {}

    # Attempt 1: full JSON parse
    try:
        parsed = json.loads(body_snippet)
        if isinstance(parsed, dict):
            result: dict[str, str] = {}
            for field in fields:
                if field in parsed:
                    v = parsed[field]
                    if isinstance(v, (str, int, float)) and v is not None:
                        result[field] = str(v)
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Attempt 2: regex extraction for known fields
    # Matches: "field_name": "value" or "field_name": 123
    field_pattern = "|".join(re.escape(f) for f in sorted(fields))
    re_pattern = re.compile(
        r'"(' + field_pattern + r')"\s*:\s*(?:"([^"]{0,200})"|(\d+))'
    )
    result = {}
    for m in re_pattern.finditer(body_snippet):
        field_name = m.group(1)
        # group(2) = string value, group(3) = integer value
        value = m.group(2) if m.group(2) is not None else m.group(3)
        if value is not None:
            result[field_name] = value

    return result


# ---------------------------------------------------------------------------
# G2 — Ownership inference
# ---------------------------------------------------------------------------


def infer_ownership_for_edge(
    edge: AccessEdge,
    principal_ids: set[str],
) -> Optional[OwnershipInference]:
    """
    Infer whether the identity that made this access likely owns the resource.

    Only produces an inference when:
    - The edge has a resource_key (concrete object was accessed)
    - The response was successful (we have meaningful response data)
    - At least one ownership-hint field is present in the response

    Confidence rules:
    - HIGH   if a primary ownership field value matches a principal ID
    - MEDIUM if a secondary ownership field value matches a principal ID
    - LOW    if ownership fields are present but no value matches any principal ID
              (we know ownership fields exist but can't determine who owns it)

    The LOW case is still useful for analyzers: it tells them the resource
    HAS an owner field, so ownership enforcement is expected at this endpoint.

    Args:
        edge: The access edge to analyze.
        principal_ids: The known principal IDs of the identity that made the request.

    Returns:
        OwnershipInference or None if no ownership signal found.
    """
    if not edge.resource_key:
        return None

    # Only useful on successful responses — errors don't give us resource data
    if edge.outcome != AccessOutcome.ALLOWED:
        return None

    # Quick pre-filter: are any ownership fields even present in the response?
    json_keys_set = set(edge.json_keys)
    has_ownership_fields = bool(json_keys_set & _ALL_OWNERSHIP_FIELDS)
    has_tenant_fields_only = bool(json_keys_set & _TENANT_FIELDS) and not has_ownership_fields

    if not has_ownership_fields and not has_tenant_fields_only:
        return None

    # Extract actual values from the body snippet
    extracted = _extract_field_values(edge.body_snippet, _ALL_OWNERSHIP_FIELDS)

    if not extracted:
        # Fields were in json_keys but we couldn't extract values (maybe truncated).
        # Record a LOW confidence "unknown" — we know ownership fields exist.
        present_fields = json_keys_set & _ALL_OWNERSHIP_FIELDS
        return OwnershipInference(
            identity_name=edge.identity_name,
            resource_key=edge.resource_key,
            conclusion=OwnershipConclusion.UNKNOWN,
            confidence=OwnershipConfidence.LOW,
            matched_field=next(iter(present_fields), None),
            matched_value=None,
            rationale=(
                f"Response contains ownership-hint field(s) "
                f"({', '.join(sorted(present_fields))}) but values could not be extracted "
                f"(body may be truncated). Cannot determine ownership."
            ),
        )

    # Check primary fields first (HIGH confidence)
    for field in _PRIMARY_OWNERSHIP_FIELDS:
        value = extracted.get(field)
        if value is None:
            continue
        if principal_ids and value in principal_ids:
            return OwnershipInference(
                identity_name=edge.identity_name,
                resource_key=edge.resource_key,
                conclusion=OwnershipConclusion.LIKELY_OWNS,
                confidence=OwnershipConfidence.HIGH,
                matched_field=field,
                matched_value=value,
                rationale=(
                    f"Response field '{field}' = '{value}' matches a known principal ID "
                    f"of identity '{edge.identity_name}'. "
                    f"High confidence that this identity owns resource '{edge.resource_key}'."
                ),
            )
        elif principal_ids:
            # Value present but doesn't match any of our principal IDs → likely not owner
            return OwnershipInference(
                identity_name=edge.identity_name,
                resource_key=edge.resource_key,
                conclusion=OwnershipConclusion.LIKELY_DOES_NOT_OWN,
                confidence=OwnershipConfidence.HIGH,
                matched_field=field,
                matched_value=value,
                rationale=(
                    f"Response field '{field}' = '{value}', which does not match any "
                    f"known principal ID of identity '{edge.identity_name}' "
                    f"({', '.join(sorted(principal_ids))}). "
                    f"High confidence that '{edge.identity_name}' does NOT own "
                    f"resource '{edge.resource_key}'."
                ),
            )

    # Check secondary fields (MEDIUM confidence)
    for field in _SECONDARY_OWNERSHIP_FIELDS:
        value = extracted.get(field)
        if value is None:
            continue
        if principal_ids and value in principal_ids:
            return OwnershipInference(
                identity_name=edge.identity_name,
                resource_key=edge.resource_key,
                conclusion=OwnershipConclusion.LIKELY_OWNS,
                confidence=OwnershipConfidence.MEDIUM,
                matched_field=field,
                matched_value=value,
                rationale=(
                    f"Response field '{field}' = '{value}' matches a known principal ID "
                    f"of identity '{edge.identity_name}' (indirect/secondary ownership hint). "
                    f"Medium confidence that this identity owns resource '{edge.resource_key}'."
                ),
            )
        elif principal_ids:
            return OwnershipInference(
                identity_name=edge.identity_name,
                resource_key=edge.resource_key,
                conclusion=OwnershipConclusion.LIKELY_DOES_NOT_OWN,
                confidence=OwnershipConfidence.MEDIUM,
                matched_field=field,
                matched_value=value,
                rationale=(
                    f"Response field '{field}' = '{value}', which does not match any "
                    f"known principal ID of identity '{edge.identity_name}'. "
                    f"Medium confidence that '{edge.identity_name}' does NOT own "
                    f"resource '{edge.resource_key}'."
                ),
            )

    # Fields present but no principal IDs configured → LOW confidence unknown
    if extracted:
        field = next(iter(extracted))
        return OwnershipInference(
            identity_name=edge.identity_name,
            resource_key=edge.resource_key,
            conclusion=OwnershipConclusion.UNKNOWN,
            confidence=OwnershipConfidence.LOW,
            matched_field=field,
            matched_value=extracted[field],
            rationale=(
                f"Response contains ownership-hint fields but identity "
                f"'{edge.identity_name}' has no configured principal IDs to compare against. "
                f"Cannot determine ownership without owned_object_ids in config."
            ),
        )

    return None


# ---------------------------------------------------------------------------
# G2 — Tenant inference
# ---------------------------------------------------------------------------


def infer_tenant_for_edge(edge: AccessEdge) -> Optional[TenantInference]:
    """
    Infer the tenant scope of the resource from a successful response.

    Looks for tenant-scoping fields in the response body.
    Only produces an inference when:
    - The edge has a resource_key (concrete object)
    - The response was successful
    - At least one tenant field is present and extractable

    Args:
        edge: The access edge to analyze.

    Returns:
        TenantInference or None if no tenant signal found.
    """
    if not edge.resource_key:
        return None
    if edge.outcome != AccessOutcome.ALLOWED:
        return None
    if not (set(edge.json_keys) & _TENANT_FIELDS):
        return None

    extracted = _extract_field_values(edge.body_snippet, _TENANT_FIELDS)
    if not extracted:
        return None

    # Pick the most specific tenant field (tenant_id > organization_id > others)
    for preferred in ("tenant_id", "organization_id", "org_id", "company_id",
                      "workspace_id", "team_id", "group_id", "account_id"):
        if preferred in extracted:
            return TenantInference(
                resource_key=edge.resource_key,
                tenant_id=extracted[preferred],
                source_field=preferred,
                identity_name=edge.identity_name,
            )

    return None


# ---------------------------------------------------------------------------
# G2 — Parent-child resource linking
# ---------------------------------------------------------------------------


def infer_parent_child_resources(graph: AuthGraph) -> None:
    """
    Link child ResourceNodes to their parent ResourceNodes.

    For child endpoints (is_child_endpoint=True), the object_id in the request
    refers to the PARENT resource, not a distinct child resource ID.

    Example:
        GET /api/orders/{id}/invoice with object_id="1001"
        → the invoice is a child of orders:1001
        → ResourceNode for the invoice gets parent_resource_key = "orders:1001"

    This mutates ResourceNode.parent_resource_key in the graph.
    It also creates ResourceNode entries for child resource instances that
    do not have their own object_id (e.g. singleton child resources like
    /profile or /invoice).

    Args:
        graph: The AuthGraph to mutate in place.
    """
    # Build parent-child endpoint map
    parent_child_ep = infer_parent_child(list(graph.endpoints.keys()))
    # Invert: parent_ep → [child_eps]
    children_of: dict[str, list[str]] = {}
    for child_ep, parent_ep in parent_child_ep.items():
        children_of.setdefault(parent_ep, []).append(child_ep)

    for parent_ep_key, child_ep_keys in children_of.items():
        for child_ep_key in child_ep_keys:
            # Find edges on the child endpoint that have an object_id
            # (the object_id is the PARENT resource's ID)
            child_edges = graph.edges_for_endpoint(child_ep_key)
            child_ep_node = graph.endpoints.get(child_ep_key)
            parent_ep_node = graph.endpoints.get(parent_ep_key)

            if not child_ep_node or not parent_ep_node:
                continue

            for edge in child_edges:
                if edge.object_id_used is None:
                    continue

                # The parent resource key
                parent_rk_str = f"{parent_ep_node.resource_type}:{edge.object_id_used}" \
                    if parent_ep_node.resource_type else None
                if not parent_rk_str:
                    continue

                # The child resource — infer a synthetic key for it
                # Use the child endpoint's path suffix as the child type
                child_suffix = _child_type_from_path(child_ep_node.path)
                if child_suffix is None:
                    continue

                child_rk_str = f"{child_suffix}:{edge.object_id_used}"

                # Create or update the child ResourceNode
                if child_rk_str not in graph.resources:
                    from bac_detector.graph.models import ResourceKey, ResourceNode
                    child_rk = ResourceKey(
                        resource_type=child_suffix,
                        resource_id=edge.object_id_used,
                        parent_key=parent_rk_str,
                    )
                    graph.resources[child_rk_str] = ResourceNode(
                        key=child_rk,
                        parent_resource_key=parent_rk_str,
                    )
                else:
                    # Update existing node with parent link if missing
                    node = graph.resources[child_rk_str]
                    if node.parent_resource_key is None:
                        node.parent_resource_key = parent_rk_str


def _child_type_from_path(path: str) -> Optional[str]:
    """
    Extract the child resource type from a child endpoint path.

    /api/orders/{id}/invoice → "invoice"
    /api/orders/{id}/items   → "items"
    /api/orders/{id}/invoice/items → "invoice"  (first sub-segment after placeholder)
    """
    segments = path.strip("/").split("/")
    brace_found = False
    for seg in segments:
        if seg.startswith("{"):
            brace_found = True
        elif brace_found and seg not in _CUSTOM_ACTION_SUFFIXES:
            return seg.lower()
    return None


# ---------------------------------------------------------------------------
# G2 — Orchestration: apply_inferences
# ---------------------------------------------------------------------------


def apply_inferences(graph: AuthGraph) -> None:
    """
    Apply all G2 inference passes to a fully-built AuthGraph.

    This is the single G2 entry point called by the builder.
    It mutates the graph in place, adding:
    - graph.ownership_inferences (OwnershipInference list)
    - graph.tenant_inferences (TenantInference list)
    - ResourceNode.attributes (owner/tenant field values from responses)
    - ResourceNode.parent_resource_key (for child resources)
    - IdentityNode.likely_principal_ids (expanded by observed ownership)

    The function runs in three passes:
    1. Ownership inference — per edge, per identity
    2. Tenant inference — per edge
    3. Parent-child resource linking — per child endpoint
    4. Resource attribute enrichment — from all inferences
    5. Identity principal ID expansion — from HIGH-confidence OWNS inferences

    Args:
        graph: The AuthGraph to enrich in place.
    """
    # Pass 1: ownership inference
    for edge in graph.edges:
        identity_node = graph.identities.get(edge.identity_name)
        if identity_node is None:
            continue
        oi = infer_ownership_for_edge(edge, identity_node.likely_principal_ids)
        if oi is not None:
            graph.ownership_inferences.append(oi)

    # Pass 2: tenant inference
    for edge in graph.edges:
        ti = infer_tenant_for_edge(edge)
        if ti is not None:
            # Deduplicate: skip if we already have this (resource, tenant_id, field) combo
            existing = {(t.resource_key, t.tenant_id, t.source_field)
                        for t in graph.tenant_inferences}
            if (ti.resource_key, ti.tenant_id, ti.source_field) not in existing:
                graph.tenant_inferences.append(ti)

    # Pass 3: parent-child resource linking (mutates ResourceNode.parent_resource_key)
    infer_parent_child_resources(graph)

    # Pass 4: enrich ResourceNode.attributes from successful edge body data
    for edge in graph.edges:
        if edge.resource_key and edge.outcome == AccessOutcome.ALLOWED:
            resource_node = graph.resources.get(edge.resource_key)
            if resource_node is None:
                continue
            extracted = _extract_field_values(
                edge.body_snippet,
                _ALL_OWNERSHIP_FIELDS | _TENANT_FIELDS,
            )
            # Merge extracted values; first non-empty value wins per field
            for field, value in extracted.items():
                if field not in resource_node.attributes:
                    resource_node.attributes[field] = value

    # Pass 5: expand identity principal IDs from HIGH-confidence OWNS inferences
    for oi in graph.ownership_inferences:
        if (oi.confidence == OwnershipConfidence.HIGH
                and oi.conclusion == OwnershipConclusion.LIKELY_OWNS
                and oi.matched_value is not None):
            identity_node = graph.identities.get(oi.identity_name)
            if identity_node:
                identity_node.likely_principal_ids.add(oi.matched_value)

    # Rebuild indexes to include new inference results
    graph._indexes_built = False
    graph._build_indexes()
