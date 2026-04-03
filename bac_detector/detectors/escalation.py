"""
Horizontal and vertical privilege escalation detectors.

Horizontal escalation: identity A accesses endpoints/objects that should
only be accessible to identity B (same privilege level, different account).
This overlaps with IDOR but focuses on endpoints without explicit object
ownership — e.g. /api/me/settings, /api/profile, /api/account.

Vertical escalation: a lower-privileged identity (user, guest) successfully
accesses an endpoint that should only be accessible to a higher-privileged
identity (admin, manager).

Detection approach:
  - Vertical: check if identities with lower-privilege roles get 2xx on
    endpoints that contain admin-like path segments, and compare against
    higher-privilege identity responses.
  - Horizontal: for endpoints without object-ID params where multiple
    same-role identities all get 2xx with different response bodies —
    they may be accessing each other's data.
"""

from __future__ import annotations

from bac_detector.analyzers.matrix import AuthMatrix
from bac_detector.comparators.response import (
    ResponseDiff,
    compare_responses,
)
from bac_detector.detectors.confidence import score_escalation_confidence
from bac_detector.models.finding import Confidence, Evidence, Finding, Severity
from bac_detector.models.identity import IdentityProfile
from bac_detector.models.response_meta import ResponseMeta
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)

# Role names considered privileged (higher privilege)
_PRIVILEGED_ROLES = frozenset(
    {"admin", "administrator", "superuser", "manager", "staff", "support"}
)

# Path segments that strongly suggest an admin/privileged endpoint.
# These are matched against individual path segments (split on "/"), so
# "superadmin" only matches if the segment is exactly "superadmin", not
# if it appears as a substring of another word.
_ADMIN_PATH_SIGNALS = frozenset({
    "admin", "superadmin", "administration",
    "internal", "internals",
    "superuser", "management",
    "staff", "root", "system",
    "dashboard", "backoffice", "back-office",
    "privileged", "ops", "operator",
    "moderator", "console", "control",
    "panel", "config", "configuration",
    "debug", "devops",
})

# Path segments associated with account-scoped endpoints (horizontal escalation candidates)
_ACCOUNT_PATH_SIGNALS = frozenset(
    {"me", "profile", "account", "settings", "preferences", "wallet", "billing"}
)


def detect_vertical_escalation(
    matrix: AuthMatrix,
    profiles: list[IdentityProfile],
) -> list[Finding]:
    """
    Detect vertical privilege escalation.

    Identifies cases where a low-privileged identity (user, guest) receives
    a 2xx response on an endpoint that shows signals of being privileged
    (admin path segments, or a response that higher-privilege identities
    also receive successfully).

    Args:
        matrix: The populated authorization matrix from Phase 3.
        profiles: All configured identity profiles.

    Returns:
        List of Finding objects for detected vertical escalation.
    """
    findings: list[Finding] = []
    role_map: dict[str, str] = {p.name: p.role for p in profiles}
    seen: set[tuple[str, str]] = set()

    for ep_key in matrix.endpoint_keys:
        path = ep_key.split(" ", 1)[-1].lower()
        path_segments = set(path.strip("/").split("/"))
        is_admin_endpoint = bool(path_segments & _ADMIN_PATH_SIGNALS)

        if not is_admin_endpoint:
            continue  # only check admin-signalled endpoints for vertical escalation

        responses_by_identity: dict[str, list[ResponseMeta]] = {}
        for identity_name in matrix.identities_for(ep_key):
            responses = matrix.responses_for_identity(ep_key, identity_name)
            if responses:
                responses_by_identity[identity_name] = responses

        if not responses_by_identity:
            continue

        # Identify higher-privilege and lower-privilege identities at this endpoint
        privileged_names = [
            n for n in responses_by_identity
            if role_map.get(n, "").lower() in _PRIVILEGED_ROLES
        ]
        lower_names = [
            n for n in responses_by_identity
            if role_map.get(n, "").lower() not in _PRIVILEGED_ROLES
        ]

        for lower_name in lower_names:
            lower_responses = responses_by_identity[lower_name]
            lower_success = [r for r in lower_responses if r.is_success]
            if not lower_success:
                continue

            lower_meta = lower_success[0]

            # Find a privileged identity's response to compare against
            higher_meta: ResponseMeta | None = None
            higher_name: str | None = None
            for priv_name in privileged_names:
                priv_responses = [
                    r for r in responses_by_identity[priv_name] if r.is_success
                ]
                if priv_responses:
                    higher_meta = priv_responses[0]
                    higher_name = priv_name
                    break

            dedup_key = (ep_key, lower_name)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            diff = compare_responses(
                candidate=lower_meta,
                reference=higher_meta or lower_meta,
            )

            confidence = score_escalation_confidence(
                lower_meta=lower_meta,
                higher_meta=higher_meta,
                diff=diff,
                is_admin_endpoint=is_admin_endpoint,
            )

            severity = _vertical_severity(confidence, is_admin_endpoint)

            finding = _build_vertical_finding(
                endpoint_key=ep_key,
                lower_identity=lower_name,
                lower_role=role_map.get(lower_name, "unknown"),
                higher_identity=higher_name,
                higher_role=role_map.get(higher_name, "unknown") if higher_name else None,
                lower_meta=lower_meta,
                higher_meta=higher_meta,
                severity=severity,
                confidence=confidence,
            )
            findings.append(finding)
            log.info(
                "vertical_escalation_finding",
                endpoint=ep_key,
                lower=lower_name,
                higher=higher_name,
                confidence=confidence.value,
            )

    return findings


def detect_horizontal_escalation(
    matrix: AuthMatrix,
    profiles: list[IdentityProfile],
) -> list[Finding]:
    """
    Detect horizontal privilege escalation.

    Identifies cases where multiple same-role identities all get 2xx on
    account-scoped endpoints with different response bodies — suggesting
    each identity is accessing distinct account data, but the access
    control may not be enforced (any credential can reach any account).

    This is a weaker signal than IDOR because we don't have cross-identity
    object ID substitution here — we just observe that the same endpoint
    returns different content for different same-role identities, which
    may indicate account-scoped data without proper ownership checks.

    Only flags POTENTIAL — horizontal escalation without explicit
    cross-identity object access cannot be CONFIRMED by the tool alone.

    Args:
        matrix: The populated authorization matrix from Phase 3.
        profiles: All configured identity profiles.

    Returns:
        List of Finding objects for potential horizontal escalation.
    """
    findings: list[Finding] = []
    role_map: dict[str, str] = {p.name: p.role for p in profiles}
    seen: set[tuple[str, str, str]] = set()

    for ep_key in matrix.endpoint_keys:
        path = ep_key.split(" ", 1)[-1].lower()
        path_segments = set(path.strip("/").split("/"))

        # Only account-scoped endpoints are candidates for horizontal escalation
        is_account_endpoint = bool(path_segments & _ACCOUNT_PATH_SIGNALS)
        if not is_account_endpoint:
            continue

        # Collect all successful responses, one per identity
        identity_names = matrix.identities_for(ep_key)
        success_map: dict[str, ResponseMeta] = {}
        for name in identity_names:
            resps = [r for r in matrix.responses_for_identity(ep_key, name) if r.is_success]
            if resps:
                success_map[name] = resps[0]

        if len(success_map) < 2:
            continue  # need at least two identities with 2xx to compare

        # Group by role — only compare same-role identities
        role_groups: dict[str, list[str]] = {}
        for name in success_map:
            role = role_map.get(name, "unknown")
            role_groups.setdefault(role, []).append(name)

        for role, names in role_groups.items():
            if len(names) < 2:
                continue  # need at least two same-role identities

            # Compare each pair of same-role identities
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    name_a, name_b = names[i], names[j]
                    meta_a = success_map[name_a]
                    meta_b = success_map[name_b]

                    diff = compare_responses(candidate=meta_a, reference=meta_b)

                    # Only flag if bodies differ — identical responses mean shared public data
                    if not diff.body_differs:
                        continue

                    # Stable dedup key: endpoint first, then sorted identity names
                    dedup_key = (ep_key, min(name_a, name_b), max(name_a, name_b))
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    finding = _build_horizontal_finding(
                        endpoint_key=ep_key,
                        identity_a=name_a,
                        identity_b=name_b,
                        role=role,
                        meta_a=meta_a,
                        meta_b=meta_b,
                        diff=diff,
                    )
                    findings.append(finding)
                    log.info(
                        "horizontal_escalation_finding",
                        endpoint=ep_key,
                        identity_a=name_a,
                        identity_b=name_b,
                        role=role,
                    )

    return findings


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _vertical_severity(confidence: Confidence, is_admin: bool) -> Severity:
    if confidence == Confidence.FP_RISK:
        return Severity.INFO
    if confidence == Confidence.CONFIRMED and is_admin:
        return Severity.CRITICAL
    if confidence == Confidence.CONFIRMED:
        return Severity.HIGH
    if is_admin:
        return Severity.HIGH
    return Severity.MEDIUM


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------


def _build_vertical_finding(
    *,
    endpoint_key: str,
    lower_identity: str,
    lower_role: str,
    higher_identity: str | None,
    higher_role: str | None,
    lower_meta: ResponseMeta,
    higher_meta: ResponseMeta | None,
    severity: Severity,
    confidence: Confidence,
) -> Finding:
    method, path = endpoint_key.split(" ", 1)

    higher_str = (
        f"'{higher_identity}' ({higher_role})"
        if higher_identity
        else "a privileged identity"
    )
    diff_summary = (
        f"'{lower_identity}' ({lower_role}) received HTTP {lower_meta.status_code}. "
        + (
            f"'{higher_identity}' received HTTP {higher_meta.status_code}."
            if higher_meta
            else "No higher-privilege baseline available."
        )
    )

    evidence = Evidence(
        attacker_identity=lower_identity,
        victim_identity=higher_identity,
        object_id=lower_meta.object_id_used,
        attacker_status_code=lower_meta.status_code,
        victim_status_code=higher_meta.status_code if higher_meta else None,
        attacker_body_snippet=lower_meta.body_snippet,
        attacker_body_hash=lower_meta.body_hash,
        diff_summary=diff_summary,
        requested_url=lower_meta.requested_url,
    )

    return Finding(
        title=f"Vertical escalation: '{lower_role}' role accessed privileged endpoint {path}",
        category="vertical_escalation",
        severity=severity,
        confidence=confidence,
        endpoint_key=endpoint_key,
        endpoint_url=lower_meta.requested_url,
        http_method=method,
        evidence=evidence,
        description=(
            f"Identity '{lower_identity}' with role '{lower_role}' successfully accessed "
            f"{path}, which appears to be a privileged endpoint. "
            f"The expected behavior is that only {higher_str} should have access."
        ),
        reproduction_steps=[
            f"Authenticate as '{lower_identity}' using its configured credentials.",
            f"Send GET {lower_meta.requested_url}",
            f"Observe HTTP {lower_meta.status_code} response — expected 401 or 403.",
        ],
        why_bac=(
            "The application does not enforce role-based access control on this endpoint. "
            "A low-privileged identity received a successful response on a path reserved "
            "for privileged roles. This constitutes vertical privilege escalation "
            "(OWASP API Security Top 10: API5 - Broken Function Level Authorization)."
        ),
        business_impact=(
            "Low-privileged users may be able to access administrative functionality, "
            "view privileged data, or perform actions reserved for admin roles. "
            "This could lead to full account takeover or data breach in severe cases."
        ),
        remediation=(
            "Implement role-based access control (RBAC) checks at the function/endpoint "
            "level. Verify the authenticated user's role before processing the request. "
            "Consider using middleware or decorators to enforce role requirements "
            "consistently across all privileged endpoints."
        ),
    )


def _build_horizontal_finding(
    *,
    endpoint_key: str,
    identity_a: str,
    identity_b: str,
    role: str,
    meta_a: ResponseMeta,
    meta_b: ResponseMeta,
    diff: ResponseDiff,
) -> Finding:
    method, path = endpoint_key.split(" ", 1)

    diff_summary = (
        f"'{identity_a}' and '{identity_b}' both received HTTP 200 at {path}, "
        f"but response bodies differ (length delta: {diff.length_delta:+d} bytes). "
        "Both identities share the same role, suggesting they may be accessing "
        "distinct account-scoped data at the same endpoint."
    )

    evidence = Evidence(
        attacker_identity=identity_a,
        victim_identity=identity_b,
        object_id=meta_a.object_id_used,
        attacker_status_code=meta_a.status_code,
        victim_status_code=meta_b.status_code,
        attacker_body_snippet=meta_a.body_snippet,
        attacker_body_hash=meta_a.body_hash,
        diff_summary=diff_summary,
        requested_url=meta_a.requested_url,
    )

    return Finding(
        title=f"Horizontal escalation candidate: {path} returns different data per identity",
        category="horizontal_escalation",
        severity=Severity.MEDIUM,
        confidence=Confidence.POTENTIAL,
        endpoint_key=endpoint_key,
        endpoint_url=meta_a.requested_url,
        http_method=method,
        evidence=evidence,
        description=(
            f"Two identities with the same role ('{role}') — '{identity_a}' and "
            f"'{identity_b}' — both received HTTP 200 at {path} with different response "
            "bodies. This suggests the endpoint serves account-scoped data. "
            "Manual testing is recommended to confirm whether cross-account access is possible."
        ),
        reproduction_steps=[
            f"Authenticate as '{identity_a}' and send GET {meta_a.requested_url}",
            "Note the response body.",
            f"Authenticate as '{identity_b}' and send the same request.",
            "Compare the two responses — if they differ, the endpoint is account-scoped.",
            f"Now send the request as '{identity_a}' but with '{identity_b}'s session token.",
            f"If the response matches '{identity_b}'s data, horizontal escalation is confirmed.",
        ],
        why_bac=(
            "Account-scoped endpoints that return different data per identity without "
            "explicit object ID parameters may rely on the session/token to scope the "
            "response. If session binding is not enforced correctly, one identity may "
            "be able to access another's data. This requires manual verification to confirm."
        ),
        business_impact=(
            "If exploitable, this could allow any authenticated user to access another "
            "user's account data (profile, settings, billing information, etc.)."
        ),
        remediation=(
            "Ensure account-scoped endpoints bind their response data strictly to the "
            "authenticated user's identity. Do not rely on client-supplied parameters "
            "to scope the response — derive scope exclusively from the verified session."
        ),
    )
