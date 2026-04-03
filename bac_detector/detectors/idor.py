"""
IDOR and BOLA detector.

Detects cases where one identity can access objects that belong to
another identity — Insecure Direct Object References (IDOR) and
Broken Object Level Authorization (BOLA).

Detection logic:
  For each endpoint with object-ID parameters:
    For each object_id in the cross-identity pool:
      For each identity that does NOT own the object:
        Compare the non-owner's response against the owner's baseline.
        If the non-owner got a 2xx with meaningful content, flag it.
"""

from __future__ import annotations

from bac_detector.analyzers.baseline import Baseline
from bac_detector.analyzers.matrix import AuthMatrix
from bac_detector.comparators.response import (
    ResponseDiff,
    compare_responses,
    is_likely_nondeterministic,
)
from bac_detector.detectors.confidence import score_idor_confidence
from bac_detector.models.finding import Confidence, Evidence, Finding, Severity
from bac_detector.models.identity import IdentityProfile
from bac_detector.models.response_meta import ResponseMeta
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)

# Path segments that suggest an admin or privileged endpoint
_ADMIN_PATH_SIGNALS = frozenset(
    {"admin", "internal", "superuser", "management", "staff", "root", "system"}
)


def detect_idor(
    matrix: AuthMatrix,
    baselines: list[Baseline],
    profiles: list[IdentityProfile],
) -> list[Finding]:
    """
    Run IDOR / BOLA detection across the authorization matrix.

    For each baseline (owner's known-good response), check whether every
    OTHER identity also got a 2xx for the same object. If they did, that's
    a likely IDOR.

    Args:
        matrix: The populated authorization matrix from Phase 3.
        baselines: Owner baselines built from the matrix.
        profiles: All configured identity profiles.

    Returns:
        List of Finding objects for detected IDOR / BOLA issues.
    """
    findings: list[Finding] = []

    # Build ownership lookup: object_id -> owner identity name
    ownership: dict[str, str] = {}
    for profile in profiles:
        for oid in profile.owned_object_ids:
            ownership.setdefault(oid, profile.name)

    # Index baselines for quick lookup: (endpoint_key, object_id) -> Baseline
    baseline_index: dict[tuple[str, str], Baseline] = {}
    for bl in baselines:
        baseline_index[(bl.endpoint_key, bl.object_id)] = bl

    # Deduplicate: track (endpoint_key, object_id, attacker) to avoid double-reporting
    seen: set[tuple[str, str, str]] = set()

    for ep_key in matrix.endpoint_keys:
        for identity_name in matrix.identities_for(ep_key):
            for meta in matrix.responses_for_identity(ep_key, identity_name):
                object_id = meta.object_id_used
                if object_id is None:
                    continue  # no object ID — IDOR not applicable
                if not meta.is_success:
                    continue  # no access — not an IDOR

                owner_name = ownership.get(object_id)
                if owner_name is None:
                    continue  # unknown ownership — no baseline possible
                if identity_name == owner_name:
                    continue  # this IS the owner — legitimate access

                dedup_key = (ep_key, object_id, identity_name)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Retrieve owner baseline for this specific object_id
                baseline = baseline_index.get((ep_key, object_id))
                owner_meta = baseline.response if baseline else None

                diff = compare_responses(
                    candidate=meta,
                    reference=owner_meta or meta,
                )

                # Check nondeterminism using only responses for THIS object_id.
                # Using all endpoint responses would incorrectly flag endpoints
                # where different object_ids naturally produce different bodies.
                oid_responses = _responses_for_object(
                    matrix, ep_key, object_id, profiles
                )
                nondeterministic = is_likely_nondeterministic(oid_responses)

                confidence = score_idor_confidence(
                    attacker_meta=meta,
                    owner_meta=owner_meta,
                    diff=diff,
                )

                # Downgrade only if responses for this specific object_id
                # look non-deterministic
                if nondeterministic and confidence == Confidence.CONFIRMED:
                    confidence = Confidence.FP_RISK

                severity = _idor_severity(ep_key, confidence)

                finding = _build_idor_finding(
                    endpoint_key=ep_key,
                    object_id=object_id,
                    attacker_name=identity_name,
                    owner_name=owner_name,
                    attacker_meta=meta,
                    owner_meta=owner_meta,
                    diff_summary=_describe_diff(diff, owner_meta),
                    severity=severity,
                    confidence=confidence,
                )
                findings.append(finding)
                log.info(
                    "idor_finding",
                    endpoint=ep_key,
                    object_id=object_id,
                    attacker=identity_name,
                    owner=owner_name,
                    confidence=confidence.value,
                )

    # Secondary pass: warn when ALL identities get the same 200 on an object
    # endpoint — this suggests authentication may not be enforced at all.
    _warn_unprotected_object_endpoints(matrix, profiles, findings, seen)

    return findings


def _warn_unprotected_object_endpoints(
    matrix: AuthMatrix,
    profiles: list[IdentityProfile],
    findings: list[Finding],
    already_seen: set[tuple[str, str, str]],
) -> None:
    """
    Append an INFO-level finding when every configured identity gets a
    successful (2xx) response with the same body on an object endpoint.

    This pattern can indicate that the endpoint is completely unauthenticated —
    i.e., authentication is not enforced at all, not just that access control
    is broken per-owner. This is distinct from IDOR (which is a cross-user
    access control failure) and needs to be surfaced separately.

    Only fires when:
    - The endpoint has an object ID parameter (object_id_used is not None).
    - All identities that were tested received a 2xx response.
    - All 2xx responses share the same body hash.
    - At least two identities were tested.
    """
    ownership: dict[str, str] = {}
    for profile in profiles:
        for oid in profile.owned_object_ids:
            ownership.setdefault(oid, profile.name)

    warn_seen: set[tuple[str, str]] = set()

    for ep_key in matrix.endpoint_keys:
        identity_names = matrix.identities_for(ep_key)
        if len(identity_names) < 2:
            continue

        # Collect per-object-id results across identities
        # object_id -> {identity_name: ResponseMeta}
        object_map: dict[str, dict[str, ResponseMeta]] = {}
        for identity_name in identity_names:
            for meta in matrix.responses_for_identity(ep_key, identity_name):
                if meta.object_id_used is None:
                    continue
                object_map.setdefault(meta.object_id_used, {})[identity_name] = meta

        for object_id, resp_map in object_map.items():
            if len(resp_map) < 2:
                continue

            # All responses must be successful (2xx)
            if not all(m.is_success for m in resp_map.values()):
                continue

            # All response body hashes must be identical
            hashes = {m.body_hash for m in resp_map.values()}
            if len(hashes) != 1:
                continue

            # Skip if already reported as IDOR
            already_reported = any(
                (ep_key, object_id, identity_name) in already_seen
                for identity_name in resp_map
            )
            if already_reported:
                continue

            dedup = (ep_key, object_id)
            if dedup in warn_seen:
                continue
            warn_seen.add(dedup)

            sample = next(iter(resp_map.values()))
            identity_list = ", ".join(f"'{n}'" for n in sorted(resp_map))

            evidence = Evidence(
                attacker_identity=sorted(resp_map)[0],
                victim_identity=None,
                object_id=object_id,
                attacker_status_code=sample.status_code,
                victim_status_code=None,
                attacker_body_snippet=sample.body_snippet,
                attacker_body_hash=sample.body_hash,
                diff_summary=(
                    f"All tested identities ({identity_list}) received HTTP "
                    f"{sample.status_code} with identical response bodies for "
                    f"object '{object_id}' at '{ep_key}'. This may indicate "
                    f"that authentication is not enforced on this endpoint."
                ),
                requested_url=sample.requested_url,
            )

            findings.append(Finding(
                title=(
                    f"Possible missing auth: all identities get identical 200 "
                    f"for object '{object_id}' at {ep_key.split(' ', 1)[-1]}"
                ),
                category="missing_auth_warning",
                severity=Severity.LOW,
                confidence=Confidence.FP_RISK,
                endpoint_key=ep_key,
                endpoint_url=sample.requested_url,
                http_method=ep_key.split(" ", 1)[0],
                evidence=evidence,
                description=(
                    f"Every configured identity ({identity_list}) received a "
                    f"successful HTTP {sample.status_code} response with the "
                    f"same body for object '{object_id}' at '{ep_key}'. "
                    f"This may mean authentication is not enforced on this "
                    f"endpoint, or that the object is intentionally public. "
                    f"Manual verification is required."
                ),
                reproduction_steps=[
                    f"Send {ep_key} without any authentication token.",
                    "If a 200 response is returned, the endpoint is unauthenticated.",
                    "If 401/403, then authentication is enforced and this is a false positive.",
                ],
                why_bac=(
                    "When all identities — including low-privilege users and guests — "
                    "receive identical successful responses for the same object ID, the "
                    "endpoint may have no authentication gate at all. An IDOR check only "
                    "detects cross-user access, not the absence of any access control."
                ),
                business_impact=(
                    "If confirmed, any unauthenticated visitor could access this object's "
                    "data without credentials. This is more severe than IDOR since it "
                    "requires no authentication at all."
                ),
                remediation=(
                    "Verify that the endpoint requires a valid authentication token. "
                    "Test without any Authorization header or cookie — if a 200 is "
                    "returned, add authentication middleware. If this is intentional "
                    "(public endpoint), document it and suppress this warning."
                ),
            ))
            log.info(
                "missing_auth_warning",
                endpoint=ep_key,
                object_id=object_id,
                identities=sorted(resp_map),
            )


def _responses_for_object(
    matrix: AuthMatrix,
    endpoint_key: str,
    object_id: str,
    profiles: list[IdentityProfile],
) -> list[ResponseMeta]:
    """
    Collect all identity responses for a specific (endpoint, object_id) pair.

    Used to scope the nondeterminism check correctly — we only want to compare
    responses that were made for the same object, not across different objects.

    Args:
        matrix: The authorization matrix.
        endpoint_key: The endpoint to look in.
        object_id: The specific object ID to filter by.
        profiles: All configured identity profiles.

    Returns:
        List of ResponseMeta where object_id_used matches the given object_id.
    """
    result: list[ResponseMeta] = []
    for identity_name in matrix.identities_for(endpoint_key):
        for meta in matrix.responses_for_identity(endpoint_key, identity_name):
            if meta.object_id_used == object_id:
                result.append(meta)
    return result


def _idor_severity(endpoint_key: str, confidence: Confidence) -> Severity:
    """
    Assign severity based on endpoint signals and confidence.

    Admin-like paths are rated higher. Confirmed findings are rated higher
    than potential findings.
    """
    path = endpoint_key.split(" ", 1)[-1].lower()
    is_admin = any(seg in path.split("/") for seg in _ADMIN_PATH_SIGNALS)

    if confidence == Confidence.FP_RISK:
        return Severity.INFO

    if is_admin:
        return Severity.CRITICAL if confidence == Confidence.CONFIRMED else Severity.HIGH

    if confidence == Confidence.CONFIRMED:
        return Severity.HIGH

    return Severity.MEDIUM


def _describe_diff(diff: ResponseDiff, owner_meta: ResponseMeta | None) -> str:
    """Build a concise human-readable summary of what was observed."""
    from bac_detector.comparators.response import ResponseDiff  # noqa: F401 — runtime type

    parts: list[str] = []
    parts.append(f"Non-owner received HTTP {diff.candidate_status}.")

    if owner_meta:
        parts.append(f"Owner received HTTP {diff.reference_status}.")
        if diff.bodies_identical:
            parts.append("Response bodies are identical to owner's response.")
        elif diff.candidate_has_extra_keys:
            parts.append(
                f"Response contains extra JSON keys not present in owner baseline: "
                f"{', '.join(diff.extra_keys[:5])}."
            )
        elif diff.body_differs:
            parts.append(
                f"Response body differs from owner baseline "
                f"(length delta: {diff.length_delta:+d} bytes)."
            )
    else:
        parts.append("No owner baseline available for comparison.")

    return " ".join(parts)


def _build_idor_finding(
    *,
    endpoint_key: str,
    object_id: str,
    attacker_name: str,
    owner_name: str,
    attacker_meta: ResponseMeta,
    owner_meta: ResponseMeta | None,
    diff_summary: str,
    severity: Severity,
    confidence: Confidence,
) -> Finding:
    """Construct a Finding for a detected IDOR / BOLA issue."""
    method, path = endpoint_key.split(" ", 1)

    evidence = Evidence(
        attacker_identity=attacker_name,
        victim_identity=owner_name,
        object_id=object_id,
        attacker_status_code=attacker_meta.status_code,
        victim_status_code=owner_meta.status_code if owner_meta else None,
        attacker_body_snippet=attacker_meta.body_snippet,
        attacker_body_hash=attacker_meta.body_hash,
        diff_summary=diff_summary,
        requested_url=attacker_meta.requested_url,
    )

    return Finding(
        title=f"IDOR: {attacker_name} accessed {owner_name}'s object at {path}",
        category="IDOR",
        severity=severity,
        confidence=confidence,
        endpoint_key=endpoint_key,
        endpoint_url=attacker_meta.requested_url,
        http_method=method,
        evidence=evidence,
        description=(
            f"Identity '{attacker_name}' successfully accessed object ID '{object_id}' "
            f"at {path}, which is owned by identity '{owner_name}'. "
            f"The server returned HTTP {attacker_meta.status_code} without enforcing "
            f"object-level ownership verification."
        ),
        reproduction_steps=[
            f"Authenticate as '{attacker_name}' using its configured credentials.",
            f"Send GET {attacker_meta.requested_url}",
            f"Observe HTTP {attacker_meta.status_code} response with resource data.",
            f"Compare response to what '{owner_name}' receives for the same request.",
        ],
        why_bac=(
            "The application returns a successful response to a non-owner identity "
            "without verifying that the requesting user has ownership or delegated "
            "access to the requested object. This is a direct violation of object-level "
            "authorization (OWASP API Security Top 10: API1 - BOLA)."
        ),
        business_impact=(
            "Any authenticated user may be able to access, read, or enumerate data "
            "belonging to other users. Depending on the data at this endpoint, this "
            "could expose PII, financial records, or other sensitive information."
        ),
        remediation=(
            "Implement per-request ownership verification: before returning a resource, "
            "confirm the authenticated user's identity matches the resource owner, or "
            "that an explicit permission delegation exists. Do not rely solely on "
            "authentication — also enforce authorization at the object level."
        ),
    )
