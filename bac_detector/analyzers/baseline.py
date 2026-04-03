"""
Baseline response builder.

A baseline captures what a legitimate owner's response looks like for a
given endpoint and object ID. The detector (Phase 4) compares other
identities' responses against this baseline to find anomalies.

The baseline is built from the authorization matrix after the replay
phase completes — it does not require any additional HTTP requests.
"""

from __future__ import annotations

from dataclasses import dataclass

from bac_detector.analyzers.matrix import AuthMatrix
from bac_detector.models.identity import IdentityProfile
from bac_detector.models.response_meta import ResponseMeta
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class Baseline:
    """
    The expected "owner" response for one (endpoint, object_id) pair.

    Captures what a legitimate owner sees when accessing their own resource.
    The detector compares non-owner responses against this.

    Attributes:
        endpoint_key: The endpoint this baseline is for.
        object_id: The object ID this baseline was captured for.
        owner_identity: The name of the identity that owns this object.
        response: The owner's ResponseMeta for this endpoint + object_id.
    """

    endpoint_key: str
    object_id: str
    owner_identity: str
    response: ResponseMeta


def build_baselines(
    matrix: AuthMatrix,
    profiles: list[IdentityProfile],
) -> list[Baseline]:
    """
    Build baseline responses for all (endpoint, identity, object_id) triples
    where the identity is the legitimate owner of the object.

    An identity is the owner of an object_id if that object_id appears in
    their owned_object_ids list. This is configured in the identity profiles.

    Args:
        matrix: The populated authorization matrix from the replay phase.
        profiles: All identity profiles (used to determine ownership).

    Returns:
        List of Baseline objects — one per (endpoint, owner, object_id) triple
        where the owner's response was a 2xx.
    """
    # Build a quick lookup: object_id -> identity_name
    ownership: dict[str, str] = {}
    for profile in profiles:
        for oid in profile.owned_object_ids:
            # If two identities claim the same ID, the first one wins
            ownership.setdefault(oid, profile.name)

    baselines: list[Baseline] = []

    for ep_key in matrix.endpoint_keys:
        for identity_name, responses_by_oid in _iter_identity_oid_responses(matrix, ep_key):
            for object_id, meta in responses_by_oid.items():
                if object_id is None:
                    continue  # no object ID — no ownership to establish
                if ownership.get(object_id) != identity_name:
                    continue  # this identity doesn't own this object
                if not meta.is_success:
                    continue  # owner got an error — can't use as baseline

                baselines.append(
                    Baseline(
                        endpoint_key=ep_key,
                        object_id=object_id,
                        owner_identity=identity_name,
                        response=meta,
                    )
                )

    log.info("baselines_built", count=len(baselines))
    return baselines


def _iter_identity_oid_responses(
    matrix: AuthMatrix,
    endpoint_key: str,
) -> list[tuple[str, dict[str | None, ResponseMeta]]]:
    """
    Iterate over (identity_name, {object_id: ResponseMeta}) for an endpoint.

    Internal helper to access the matrix's internal structure without
    exposing the defaultdict directly.
    """
    result = []
    for identity_name in matrix.identities_for(endpoint_key):
        oid_map: dict[str | None, ResponseMeta] = {}
        for response in matrix.responses_for_identity(endpoint_key, identity_name):
            oid_map[response.object_id_used] = response
        result.append((identity_name, oid_map))
    return result
