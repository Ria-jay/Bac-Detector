"""
Request builder for the replay engine.

Converts an Endpoint + IdentityProfile into a concrete, sendable
httpx request — resolving path templates, attaching auth, and
collecting all parameters needed for one HTTP call.
"""

from __future__ import annotations

from dataclasses import dataclass

from bac_detector.auth.profiles import build_request_cookies, build_request_headers
from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter
from bac_detector.models.identity import IdentityProfile
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class PreparedRequest:
    """
    A fully-resolved HTTP request ready to be sent.

    Produced by build_requests() for each (endpoint, identity, object_id)
    combination. Carries everything the executor needs without any
    further resolution.
    """

    method: str
    url: str
    headers: dict[str, str]
    cookies: dict[str, str]
    # The object ID that was substituted into the path/query, if any
    object_id_used: str | None
    # The canonical endpoint key for matrix indexing
    endpoint_key: str
    # Identity name for matrix indexing
    identity_name: str


def build_requests(
    endpoint: Endpoint,
    identities: list[IdentityProfile],
    *,
    object_ids: list[str] | None = None,
) -> list[PreparedRequest]:
    """
    Build one PreparedRequest per (identity, object_id) combination.

    For endpoints that have no object-ID path parameters, one request
    per identity is produced (object_id_used=None).

    For endpoints with object-ID path parameters, one request per
    (identity, object_id) combination is produced, substituting the
    object_id into the path template.

    Only GET requests are produced in MVP. Write methods are skipped
    at the builder level so callers never accidentally send mutations.

    Args:
        endpoint: The endpoint to build requests for.
        identities: All identity profiles to replay across.
        object_ids: Concrete object IDs to substitute. When None and
                    the endpoint has object-ID params, the example
                    values from the spec are used as a fallback.

    Returns:
        List of PreparedRequest instances, one per (identity, object_id).
    """
    if endpoint.method != HttpMethod.GET:
        log.debug(
            "replay_builder_skip_non_get",
            endpoint=endpoint.endpoint_key,
            method=endpoint.method.value,
        )
        return []

    id_params = endpoint.object_id_params

    if not id_params:
        # No object-ID params — one plain request per identity
        return [
            _build_one(endpoint, identity, object_id=None)
            for identity in identities
        ]

    # Collect object IDs to use for substitution
    effective_ids = _resolve_object_ids(id_params, object_ids)

    if not effective_ids:
        # No IDs available — fall back to one plain request per identity
        # (path template left unresolved, e.g. /api/users/{id})
        log.debug(
            "replay_builder_no_object_ids",
            endpoint=endpoint.endpoint_key,
        )
        return [
            _build_one(endpoint, identity, object_id=None)
            for identity in identities
        ]

    # Build one request per identity per object_id
    requests: list[PreparedRequest] = []
    for identity in identities:
        for oid in effective_ids:
            requests.append(_build_one(endpoint, identity, object_id=oid))
    return requests


def _resolve_object_ids(
    id_params: list[Parameter],
    provided_ids: list[str] | None,
) -> list[str]:
    """
    Determine which object IDs to use for path substitution.

    Priority:
      1. Caller-provided IDs (from identity owned_object_ids, cross-identity pool)
      2. Example values from the spec parameters
      3. Empty list (caller will fall back to un-substituted template)
    """
    if provided_ids:
        return list(provided_ids)

    # Try example values from any object-ID parameter
    examples = [
        p.example_value
        for p in id_params
        if p.example_value is not None
    ]
    return examples[:1]  # one example is enough as a baseline placeholder


def _build_one(
    endpoint: Endpoint,
    identity: IdentityProfile,
    object_id: str | None,
) -> PreparedRequest:
    """
    Build a single PreparedRequest for one (endpoint, identity, object_id) triple.

    Args:
        endpoint: The target endpoint.
        identity: The identity to authenticate as.
        object_id: Object ID to substitute into path params, or None.

    Returns:
        PreparedRequest ready for the executor.
    """
    url = _resolve_url(endpoint, object_id)
    headers = build_request_headers(identity)
    cookies = build_request_cookies(identity)

    return PreparedRequest(
        method=endpoint.method.value,
        url=url,
        headers=headers,
        cookies=cookies,
        object_id_used=object_id,
        endpoint_key=endpoint.endpoint_key,
        identity_name=identity.name,
    )


def _resolve_url(endpoint: Endpoint, object_id: str | None) -> str:
    """
    Produce a concrete URL from an endpoint template.

    If object_id is provided and the path contains {param} placeholders,
    the first object-ID parameter placeholder is substituted with object_id.
    All other placeholders are left in place (they are not object IDs and
    the executor will send them as-is — the server will 400/404 which is
    fine for BAC baseline detection).

    Args:
        endpoint: The endpoint with a (possibly templated) path.
        object_id: The concrete ID to substitute, or None.

    Returns:
        Full URL string.
    """
    base = endpoint.base_url.rstrip("/")
    path = endpoint.path

    if object_id is not None and "{" in path:
        # Substitute the first object-ID param placeholder
        id_params = endpoint.object_id_params
        if id_params:
            first_param = id_params[0]
            placeholder = "{" + first_param.name + "}"
            # Also handle generic {id} placeholder from normalization
            if placeholder in path:
                path = path.replace(placeholder, object_id, 1)
            elif "{id}" in path:
                path = path.replace("{id}", object_id, 1)

    return f"{base}{path}"
