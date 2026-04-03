"""
Authorization Graph — G3 analyzers.

Six graph-based detectors that reason across relationships, not just
isolated request pairs. Each analyzer takes an AuthGraph and returns
a list of Finding objects using the existing finding models.

Analyzers
---------
1. inconsistent_sibling_action   — identity denied one action but allowed another
                                   on the same resource / resource family
2. child_resource_exposure       — parent denied but child/sub-resource allowed
3. hidden_privilege_path         — main admin endpoint denied but a sub-action
                                   under the same admin namespace allowed
4. tenant_boundary_inconsistency — resource appears to belong to a different tenant
                                   than the requesting identity
5. ownership_inconsistency       — identity accesses a resource they likely don't own,
                                   while sibling endpoints show different enforcement
6. partial_authorization         — endpoints in the same resource family enforce
                                   authorization inconsistently

Each analyzer is a standalone function so it can be tested independently,
enabled/disabled via config, and understood without reading the others.
"""

from __future__ import annotations

from bac_detector.graph.inference import infer_parent_child
from bac_detector.graph.models import (
    AccessEdge,
    AccessOutcome,
    ActionType,
    AuthGraph,
    OwnershipConfidence,
    OwnershipConclusion,
)
from bac_detector.models.finding import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# 1. Inconsistent sibling action protection
# ---------------------------------------------------------------------------

def analyze_inconsistent_sibling_actions(graph: AuthGraph) -> list[Finding]:
    """
    Flag when an identity is denied one action on a resource family but
    allowed a closely related action on the same family.

    This detects cases like:
      - GET /orders/1001        → 403  (denied)
      - PATCH /orders/1001      → 200  (allowed — can update but not read?)
      - DELETE /orders/1001     → 200  (allowed — can delete but not read?)

    Detection logic:
      For each resource family, for each identity:
        Collect all ALLOWED and DENIED outcomes per endpoint.
        If at least one endpoint is DENIED and at least one is ALLOWED,
        and the ALLOWED action is at least as sensitive as the DENIED one,
        flag it.

    Confidence:
      CONFIRMED if both ALLOWED and DENIED responses were observed for the
      same object_id (same resource instance).
      POTENTIAL otherwise.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()  # (family, identity, denied_ep)

    for family in graph.families:
        for identity_name in graph.identities:
            denied_edges: list[AccessEdge] = []
            allowed_edges: list[AccessEdge] = []

            for ep_key in family.endpoint_keys:
                for edge in graph.edges_for_identity_endpoint(identity_name, ep_key):
                    if edge.outcome == AccessOutcome.DENIED:
                        denied_edges.append(edge)
                    elif edge.outcome == AccessOutcome.ALLOWED:
                        allowed_edges.append(edge)

            if not denied_edges or not allowed_edges:
                continue

            # Find the most interesting pair: a SENSITIVE allowed action
            # paired with a denied action
            for denied in denied_edges:
                for allowed in allowed_edges:
                    if denied.endpoint_key == allowed.endpoint_key:
                        continue  # same endpoint different object — not sibling

                    dedup = (family.resource_type, identity_name, denied.endpoint_key)
                    if dedup in seen:
                        continue
                    seen.add(dedup)

                    same_object = (
                        denied.object_id_used is not None
                        and denied.object_id_used == allowed.object_id_used
                    )
                    confidence = Confidence.CONFIRMED if same_object else Confidence.POTENTIAL

                    evidence = _make_evidence(
                        attacker=identity_name,
                        attacker_status=allowed.status_code,
                        victim_status=denied.status_code,
                        object_id=allowed.object_id_used or denied.object_id_used,
                        url=allowed.endpoint_key,
                        diff=(
                            f"'{identity_name}' was DENIED {denied.action.value} on "
                            f"'{denied.endpoint_key}' (HTTP {denied.status_code}) "
                            f"but ALLOWED {allowed.action.value} on "
                            f"'{allowed.endpoint_key}' (HTTP {allowed.status_code}) "
                            f"within the same '{family.resource_type}' resource family."
                        ),
                    )

                    findings.append(Finding(
                        title=(
                            f"Inconsistent protection: '{identity_name}' denied "
                            f"{denied.action.value} but allowed {allowed.action.value} "
                            f"on '{family.resource_type}'"
                        ),
                        category="graph_sibling_inconsistency",
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        endpoint_key=allowed.endpoint_key,
                        endpoint_url=allowed.endpoint_key,
                        http_method=allowed.endpoint_key.split(" ", 1)[0],
                        evidence=evidence,
                        description=(
                            f"Identity '{identity_name}' is denied access to "
                            f"'{denied.endpoint_key}' ({denied.action.value}) but is "
                            f"allowed to perform '{allowed.action.value}' on a sibling "
                            f"endpoint '{allowed.endpoint_key}' within the same "
                            f"'{family.resource_type}' resource family. "
                            f"This suggests authorization is applied inconsistently "
                            f"across actions on the same resource."
                        ),
                        reproduction_steps=[
                            f"Authenticate as '{identity_name}'.",
                            f"Send {denied.endpoint_key} — observe HTTP {denied.status_code} (denied).",
                            f"Send {allowed.endpoint_key} — observe HTTP {allowed.status_code} (allowed).",
                            "Both requests act on the same resource family. "
                            "One should be at least as restricted as the other.",
                        ],
                        why_bac=(
                            "Authorization controls should be applied consistently across all "
                            "actions within the same resource family. Allowing a more sensitive "
                            "or equivalent action while denying a less sensitive one often "
                            "indicates missing or incomplete authorization checks."
                        ),
                        business_impact=(
                            "An attacker may exploit the allowed action to access or modify "
                            "data they should not have access to, bypassing the denied action's "
                            "intended protection."
                        ),
                        remediation=(
                            "Review authorization logic for all endpoints in the "
                            f"'{family.resource_type}' resource family. Ensure that the same "
                            "ownership and role checks are applied consistently across all "
                            "actions. Consider centralizing authorization logic for the "
                            "resource family."
                        ),
                    ))

    log.info("graph_analyzer_sibling", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# 2. Child-resource exposure
# ---------------------------------------------------------------------------

def analyze_child_resource_exposure(graph: AuthGraph) -> list[Finding]:
    """
    Flag when a parent resource is denied but a child/sub-resource is accessible.

    This detects:
      - GET /orders/1001          → 403
      - GET /orders/1001/invoice  → 200

    Detection logic:
      Use the parent-child endpoint map to find (parent_ep, child_eps) pairs.
      For each identity:
        If parent is DENIED and child is ALLOWED (for matching object_id), flag it.

    Confidence: CONFIRMED if same object_id, POTENTIAL otherwise.
    """
    findings: list[Finding] = []
    parent_child = infer_parent_child(list(graph.endpoints.keys()))
    # Invert: parent_ep → [child_eps]
    children_of: dict[str, list[str]] = {}
    for child_ep, parent_ep in parent_child.items():
        children_of.setdefault(parent_ep, []).append(child_ep)

    seen: set[tuple[str, str, str]] = set()

    for parent_ep, child_eps in children_of.items():
        for identity_name in graph.identities:
            parent_edges = graph.edges_for_identity_endpoint(identity_name, parent_ep)
            denied_parent = [e for e in parent_edges if e.outcome == AccessOutcome.DENIED]
            if not denied_parent:
                continue

            for child_ep in child_eps:
                child_edges = graph.edges_for_identity_endpoint(identity_name, child_ep)
                allowed_child = [e for e in child_edges if e.outcome == AccessOutcome.ALLOWED]
                if not allowed_child:
                    continue

                for dp in denied_parent:
                    for ac in allowed_child:
                        dedup = (identity_name, parent_ep, child_ep)
                        if dedup in seen:
                            continue
                        seen.add(dedup)

                        same_obj = (
                            dp.object_id_used is not None
                            and dp.object_id_used == ac.object_id_used
                        )
                        confidence = Confidence.CONFIRMED if same_obj else Confidence.POTENTIAL

                        evidence = _make_evidence(
                            attacker=identity_name,
                            attacker_status=ac.status_code,
                            victim_status=dp.status_code,
                            object_id=dp.object_id_used or ac.object_id_used,
                            url=ac.endpoint_key,
                            diff=(
                                f"Parent '{parent_ep}' returned HTTP {dp.status_code} "
                                f"(denied), but child '{child_ep}' returned HTTP "
                                f"{ac.status_code} (allowed) for identity '{identity_name}'."
                            ),
                        )

                        child_suffix = child_ep.split(parent_ep.split("{")[0], 1)[-1] \
                            if parent_ep.split("{")[0] in child_ep else child_ep

                        findings.append(Finding(
                            title=(
                                f"Child-resource exposure: '{identity_name}' denied "
                                f"parent access but allowed child access"
                            ),
                            category="graph_child_exposure",
                            severity=Severity.HIGH,
                            confidence=confidence,
                            endpoint_key=child_ep,
                            endpoint_url=child_ep,
                            http_method=child_ep.split(" ", 1)[0],
                            evidence=evidence,
                            description=(
                                f"Identity '{identity_name}' is denied access to the "
                                f"parent resource at '{parent_ep}' (HTTP {dp.status_code}), "
                                f"but can still access the child resource at '{child_ep}' "
                                f"(HTTP {ac.status_code}). "
                                f"The child resource likely contains data derived from or "
                                f"related to the parent, meaning the parent-level denial is "
                                f"not enforced on sub-resources."
                            ),
                            reproduction_steps=[
                                f"Authenticate as '{identity_name}'.",
                                f"Send {parent_ep} — observe HTTP {dp.status_code} (denied).",
                                f"Send {child_ep} — observe HTTP {ac.status_code} (allowed).",
                                "The child endpoint is accessible despite the parent being denied.",
                            ],
                            why_bac=(
                                "Object-level authorization on a parent resource should extend "
                                "to all its child and related resources. Denying access at the "
                                "parent level but allowing it at child endpoints defeats the "
                                "intended access control and may expose sensitive sub-data "
                                "(OWASP API1: Broken Object Level Authorization)."
                            ),
                            business_impact=(
                                "Sensitive data accessible only through the child endpoint "
                                "(invoices, line items, attachments, etc.) may be exposed to "
                                "identities that were explicitly denied the parent resource."
                            ),
                            remediation=(
                                "Propagate authorization checks from the parent resource to all "
                                "child and related endpoints. Implement a shared authorization "
                                "function that verifies access to the parent before serving any "
                                "child resource request."
                            ),
                        ))

    log.info("graph_analyzer_child_exposure", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# 3. Hidden privilege path
# ---------------------------------------------------------------------------

def analyze_hidden_privilege_path(graph: AuthGraph) -> list[Finding]:
    """
    Flag when the main admin endpoint is denied but a specific sub-action
    under the same admin namespace is accessible.

    This detects:
      - GET /admin/users           → 403
      - POST /admin/users/5/disable → 200

    Detection logic:
      For each identity with role NOT in _PRIVILEGED_ROLES:
        Find admin-family endpoints (ActionType.ADMIN_ACTION).
        If any admin endpoint is DENIED and any OTHER admin endpoint is ALLOWED,
        flag it.
    """
    findings: list[Finding] = []
    _PRIVILEGED = frozenset({"admin", "administrator", "superuser", "manager", "staff"})

    seen: set[tuple[str, str, str]] = set()

    # Collect all admin endpoints
    admin_ep_keys = [
        ep_key for ep_key, ep_node in graph.endpoints.items()
        if ep_node.action == ActionType.ADMIN_ACTION
    ]
    if len(admin_ep_keys) < 2:
        return findings

    for identity_name, identity_node in graph.identities.items():
        if identity_node.role.lower() in _PRIVILEGED:
            continue  # privileged roles are expected to access admin endpoints

        denied_admin: list[AccessEdge] = []
        allowed_admin: list[AccessEdge] = []

        for ep_key in admin_ep_keys:
            for edge in graph.edges_for_identity_endpoint(identity_name, ep_key):
                if edge.outcome == AccessOutcome.DENIED:
                    denied_admin.append(edge)
                elif edge.outcome == AccessOutcome.ALLOWED:
                    allowed_admin.append(edge)

        if not denied_admin or not allowed_admin:
            continue

        for denied in denied_admin:
            for allowed in allowed_admin:
                if denied.endpoint_key == allowed.endpoint_key:
                    continue

                dedup = (identity_name, denied.endpoint_key, allowed.endpoint_key)
                if dedup in seen:
                    continue
                seen.add(dedup)

                evidence = _make_evidence(
                    attacker=identity_name,
                    attacker_status=allowed.status_code,
                    victim_status=denied.status_code,
                    object_id=allowed.object_id_used,
                    url=allowed.endpoint_key,
                    diff=(
                        f"'{identity_name}' ({identity_node.role}) denied "
                        f"'{denied.endpoint_key}' (HTTP {denied.status_code}) "
                        f"but allowed '{allowed.endpoint_key}' (HTTP {allowed.status_code})."
                    ),
                )

                findings.append(Finding(
                    title=(
                        f"Hidden privilege path: '{identity_name}' denied main admin "
                        f"endpoint but reached '{allowed.endpoint_key}'"
                    ),
                    category="graph_hidden_privilege_path",
                    severity=Severity.HIGH,
                    confidence=Confidence.POTENTIAL,
                    endpoint_key=allowed.endpoint_key,
                    endpoint_url=allowed.endpoint_key,
                    http_method=allowed.endpoint_key.split(" ", 1)[0],
                    evidence=evidence,
                    description=(
                        f"Identity '{identity_name}' (role: '{identity_node.role}') is "
                        f"denied access to '{denied.endpoint_key}' but can reach "
                        f"'{allowed.endpoint_key}', which is also an admin-namespace "
                        f"endpoint. This suggests that the admin namespace is only partially "
                        f"protected — specific sub-actions are accessible even when the "
                        f"main admin resource is denied."
                    ),
                    reproduction_steps=[
                        f"Authenticate as '{identity_name}' (role: {identity_node.role}).",
                        f"Send {denied.endpoint_key} — observe HTTP {denied.status_code} (denied).",
                        f"Send {allowed.endpoint_key} — observe HTTP {allowed.status_code} (allowed).",
                        "Both endpoints are in the admin namespace. The second should require "
                        "at least as much privilege as the first.",
                    ],
                    why_bac=(
                        "Privilege boundaries should be enforced at the namespace level, not "
                        "just at individual endpoints. Allowing specific admin sub-actions "
                        "to lower-privileged roles while denying the main admin resource "
                        "creates hidden privilege escalation paths "
                        "(OWASP API5: Broken Function Level Authorization)."
                    ),
                    business_impact=(
                        "A low-privileged user may be able to invoke privileged operations "
                        "(disable accounts, promote users, access audit logs, etc.) through "
                        "admin sub-endpoints that lack proper role checks."
                    ),
                    remediation=(
                        "Apply role-based authorization at the admin namespace level, not just "
                        "at individual endpoints. Consider a single middleware layer that "
                        "enforces admin role requirements for all paths under /admin/ (or "
                        "equivalent)."
                    ),
                ))

    log.info("graph_analyzer_hidden_privilege", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# 4. Tenant boundary inconsistency
# ---------------------------------------------------------------------------

def analyze_tenant_boundary_inconsistency(graph: AuthGraph) -> list[Finding]:
    """
    Flag when a resource's inferred tenant_id does not match any expected
    tenant scope of the accessing identity.

    This detects:
      - Identity alice (principal_ids = {"user-1"}) accesses order:1001
      - Response shows tenant_id = "tenant-B"
      - But alice's other resources all show tenant_id = "tenant-A"

    Detection logic:
      For each identity that has multiple resource accesses:
        Collect all inferred tenant_ids across their accessed resources.
        If two resources (or two identities accessing the same resource)
        show DIFFERENT tenant_ids, flag the inconsistency.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    # Check per-resource: do different identities see different tenant_ids?
    for resource_key in graph.resources:
        tenant_infs = graph.tenant_for_resource(resource_key)
        if len(tenant_infs) < 2:
            continue

        tenant_ids_seen = {ti.tenant_id for ti in tenant_infs}
        if len(tenant_ids_seen) <= 1:
            continue  # all identities see same tenant — consistent

        # Multiple different tenant_ids for the same resource across identities
        for ti in tenant_infs:
            other_tenants = tenant_ids_seen - {ti.tenant_id}
            dedup = (ti.identity_name, resource_key)
            if dedup in seen:
                continue
            seen.add(dedup)

            evidence = _make_evidence(
                attacker=ti.identity_name,
                attacker_status=200,
                object_id=resource_key.split(":", 1)[-1] if ":" in resource_key else None,
                url=f"resource:{resource_key}",
                diff=(
                    f"For resource '{resource_key}', identity '{ti.identity_name}' "
                    f"observed tenant_id='{ti.tenant_id}' (via field '{ti.source_field}'). "
                    f"Other identities observed tenant_id(s): "
                    f"{', '.join(repr(t) for t in sorted(other_tenants))}."
                ),
            )

            findings.append(Finding(
                title=(
                    f"Tenant boundary inconsistency on '{resource_key}': "
                    f"multiple tenant IDs observed"
                ),
                category="graph_tenant_boundary",
                severity=Severity.MEDIUM,
                confidence=Confidence.POTENTIAL,
                endpoint_key=f"resource:{resource_key}",
                endpoint_url=f"resource:{resource_key}",
                http_method="GET",
                evidence=evidence,
                description=(
                    f"Different identities accessing resource '{resource_key}' observed "
                    f"different tenant_id values in the response body: "
                    f"{', '.join(repr(t) for t in sorted(tenant_ids_seen))}. "
                    f"This may indicate that one identity is accessing a resource belonging "
                    f"to a different tenant, suggesting a tenant boundary violation."
                ),
                reproduction_steps=[
                    f"Access resource '{resource_key}' as different identities.",
                    "Compare the tenant_id field in each response.",
                    "If tenant_ids differ, one identity may be accessing cross-tenant data.",
                ],
                why_bac=(
                    "In multi-tenant applications, each resource should be scoped to a "
                    "single tenant. If different identities see different tenant_id values "
                    "for the same resource key, it may indicate that tenant isolation is "
                    "not enforced at the object level."
                ),
                business_impact=(
                    "Cross-tenant data exposure could allow one tenant to access another's "
                    "sensitive data, violating data isolation guarantees and potentially "
                    "regulatory compliance requirements."
                ),
                remediation=(
                    "Ensure every data access operation includes a tenant scoping filter. "
                    "Validate that the authenticated user's tenant matches the resource's "
                    "tenant before returning data. Consider adding tenant_id to all primary "
                    "keys at the database level."
                ),
            ))

    log.info("graph_analyzer_tenant_boundary", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# 5. Ownership inconsistency
# ---------------------------------------------------------------------------

def analyze_ownership_inconsistency(graph: AuthGraph) -> list[Finding]:
    """
    Flag when an identity accesses a resource they likely don't own, and
    sibling endpoints in the same family show inconsistent ownership enforcement.

    This is stronger than basic IDOR detection because it uses G2 ownership
    inference to show not just "access happened" but also "the response body
    suggests this identity doesn't own the resource".

    Detection logic:
      For each identity, for each resource key:
        If best_ownership_inference → LIKELY_DOES_NOT_OWN (HIGH/MEDIUM confidence)
        AND an ALLOWED access edge exists for that resource:
          Flag it.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for identity_name in graph.identities:
        for edge in graph.edges_for_identity(identity_name):
            if edge.outcome != AccessOutcome.ALLOWED:
                continue
            if not edge.resource_key:
                continue

            dedup = (identity_name, edge.resource_key)
            if dedup in seen:
                continue

            oi = graph.best_ownership_inference(identity_name, edge.resource_key)
            if oi is None:
                continue
            if oi.conclusion != OwnershipConclusion.LIKELY_DOES_NOT_OWN:
                continue
            # Only flag HIGH and MEDIUM — LOW is too uncertain
            if oi.confidence not in (
                OwnershipConfidence.HIGH,
                OwnershipConfidence.MEDIUM,
            ):
                continue

            seen.add(dedup)

            confidence = (
                Confidence.CONFIRMED
                if oi.confidence.value == "high"
                else Confidence.POTENTIAL
            )

            evidence = _make_evidence(
                attacker=identity_name,
                attacker_status=edge.status_code,
                object_id=edge.object_id_used,
                url=edge.endpoint_key,
                diff=(
                    f"Identity '{identity_name}' received HTTP {edge.status_code} "
                    f"for resource '{edge.resource_key}'. "
                    f"Ownership inference: {oi.rationale}"
                ),
            )

            findings.append(Finding(
                title=(
                    f"Ownership inconsistency: '{identity_name}' accessed "
                    f"'{edge.resource_key}' without ownership"
                ),
                category="graph_ownership_inconsistency",
                severity=Severity.HIGH,
                confidence=confidence,
                endpoint_key=edge.endpoint_key,
                endpoint_url=edge.endpoint_key,
                http_method=edge.endpoint_key.split(" ", 1)[0],
                evidence=evidence,
                description=(
                    f"Identity '{identity_name}' successfully accessed resource "
                    f"'{edge.resource_key}' at endpoint '{edge.endpoint_key}', "
                    f"but the response body indicates this identity does not own the resource. "
                    f"Evidence: {oi.rationale}"
                ),
                reproduction_steps=[
                    f"Authenticate as '{identity_name}'.",
                    f"Send {edge.endpoint_key}.",
                    f"Observe HTTP {edge.status_code} — access granted.",
                    f"Inspect response body: field '{oi.matched_field}' = '{oi.matched_value}' "
                    f"does not match any known principal ID of '{identity_name}'.",
                ],
                why_bac=(
                    "The server returned a successful response to an identity whose principal "
                    "ID does not match the resource's ownership field. This is a direct "
                    "violation of object-level authorization — the server should verify "
                    "that the requesting identity owns the resource before returning it "
                    "(OWASP API1: BOLA/IDOR)."
                ),
                business_impact=(
                    "An authenticated user can read data belonging to another user. "
                    "Depending on the data at this endpoint, this could expose PII, "
                    "financial records, or other sensitive information."
                ),
                remediation=(
                    "Add an ownership check before returning the resource: verify that the "
                    f"'{oi.matched_field}' in the response matches the authenticated user's "
                    "principal ID. Perform this check at the data access layer, not just "
                    "at the routing layer."
                ),
            ))

    log.info("graph_analyzer_ownership_inconsistency", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# 6. Partial authorization enforcement
# ---------------------------------------------------------------------------

def analyze_partial_authorization(graph: AuthGraph) -> list[Finding]:
    """
    Flag when endpoints in the same resource family enforce authorization
    inconsistently across identities.

    A resource family has partial authorization enforcement when:
    - Some endpoints in the family correctly deny unauthorized identities
    - Other endpoints in the same family allow those same identities

    This differs from child-resource exposure (which is parent→child) by
    looking at the full family: any endpoint in the family that allows
    while a sibling denies for the same identity at the same privilege level.

    Detection logic:
      For each resource family with ≥3 endpoints:
        Count how many endpoints ALLOW vs DENY for each non-privileged identity.
        If both counts > 0 (mixed enforcement), flag it.
        Rate severity by the proportion of allowed endpoints.
    """
    findings: list[Finding] = []
    _PRIVILEGED = frozenset({"admin", "administrator", "superuser", "manager"})
    seen: set[tuple[str, str]] = set()

    for family in graph.families:
        if len(family.endpoint_keys) < 3:
            continue  # need enough endpoints to make "partial" meaningful

        for identity_name, identity_node in graph.identities.items():
            if identity_node.role.lower() in _PRIVILEGED:
                continue

            allowed_eps: list[str] = []
            denied_eps: list[str] = []

            for ep_key in family.endpoint_keys:
                edges = graph.edges_for_identity_endpoint(identity_name, ep_key)
                if not edges:
                    continue
                outcomes = {e.outcome for e in edges}
                if AccessOutcome.ALLOWED in outcomes:
                    allowed_eps.append(ep_key)
                elif AccessOutcome.DENIED in outcomes:
                    denied_eps.append(ep_key)

            if not allowed_eps or not denied_eps:
                continue  # either all allowed or all denied — consistent

            dedup = (family.resource_type, identity_name)
            if dedup in seen:
                continue
            seen.add(dedup)

            allowed_ratio = len(allowed_eps) / (len(allowed_eps) + len(denied_eps))
            # Higher ratio of allowed = more severe (more enforcement gaps)
            severity = Severity.HIGH if allowed_ratio >= 0.5 else Severity.MEDIUM

            sample_allowed = allowed_eps[0]
            sample_denied = denied_eps[0]
            sample_edge = (graph.edges_for_identity_endpoint(identity_name, sample_allowed) or [None])[0]

            evidence = _make_evidence(
                attacker=identity_name,
                attacker_status=sample_edge.status_code if sample_edge else 200,
                object_id=sample_edge.object_id_used if sample_edge else None,
                url=sample_allowed,
                diff=(
                    f"Identity '{identity_name}' has mixed access in the "
                    f"'{family.resource_type}' family: ALLOWED at "
                    f"{len(allowed_eps)} endpoint(s) "
                    f"({', '.join(allowed_eps[:2])}{'...' if len(allowed_eps)>2 else ''}), "
                    f"DENIED at {len(denied_eps)} endpoint(s) "
                    f"({', '.join(denied_eps[:2])}{'...' if len(denied_eps)>2 else ''})."
                ),
            )

            findings.append(Finding(
                title=(
                    f"Partial authorization in '{family.resource_type}' family: "
                    f"'{identity_name}' allowed at {len(allowed_eps)}/{len(allowed_eps)+len(denied_eps)} endpoints"
                ),
                category="graph_partial_authorization",
                severity=severity,
                confidence=Confidence.POTENTIAL,
                endpoint_key=sample_allowed,
                endpoint_url=sample_allowed,
                http_method=sample_allowed.split(" ", 1)[0],
                evidence=evidence,
                description=(
                    f"Identity '{identity_name}' has inconsistent access within the "
                    f"'{family.resource_type}' resource family. "
                    f"Access is ALLOWED at {len(allowed_eps)} endpoint(s) but DENIED "
                    f"at {len(denied_eps)} endpoint(s) within the same family. "
                    f"This suggests authorization is applied to some endpoints but not "
                    f"others — a sign of partial or incremental security implementation."
                ),
                reproduction_steps=[
                    f"Authenticate as '{identity_name}'.",
                    f"Denied: {', '.join(denied_eps[:3])}",
                    f"Allowed: {', '.join(allowed_eps[:3])}",
                    "Compare the authorization logic for each endpoint in the family.",
                ],
                why_bac=(
                    "Authorization within a resource family should be applied uniformly. "
                    "Partial enforcement—where some endpoints are protected and others "
                    "are not—typically arises when authorization is added endpoint-by-endpoint "
                    "rather than at a resource level. This leaves gaps that can be exploited "
                    "(OWASP API5: Broken Function Level Authorization)."
                ),
                business_impact=(
                    "Attackers can enumerate the unprotected endpoints in a resource family "
                    "to access data or functionality intended to be restricted."
                ),
                remediation=(
                    f"Audit all endpoints in the '{family.resource_type}' resource family "
                    "and apply consistent authorization logic. Consider implementing "
                    "authorization as a shared decorator or middleware that covers the entire "
                    "resource family rather than per-endpoint checks."
                ),
            ))

    log.info("graph_analyzer_partial_auth", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_evidence(
    *,
    attacker: str,
    attacker_status: int,
    diff: str,
    url: str,
    victim: str | None = None,
    victim_status: int | None = None,
    object_id: str | None = None,
) -> Evidence:
    """Build an Evidence object for a graph finding."""
    return Evidence(
        attacker_identity=attacker,
        victim_identity=victim,
        object_id=object_id,
        attacker_status_code=attacker_status,
        victim_status_code=victim_status,
        attacker_body_snippet="",
        attacker_body_hash="graph_inference",
        diff_summary=diff,
        requested_url=url,
    )
