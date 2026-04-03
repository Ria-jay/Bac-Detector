"""
Authorization matrix builder.

The matrix is the central data structure for BAC detection.
It records every response outcome as a cell:

    endpoint_key  x  identity_name  x  object_id  ->  ResponseMeta

This lets the detector (Phase 4) ask:
  - Did identity A get a 200 for object_id that belongs to identity B?
  - Does the admin endpoint return 200 for a guest identity?
  - Is there a difference in response shape across identities for the same object?
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from bac_detector.models.response_meta import ResponseMeta
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class AuthMatrix:
    """
    The authorization matrix produced by the replay phase.

    Stores ResponseMeta objects indexed by (endpoint_key, identity_name, object_id).
    Provides query helpers used by the detector phase.

    The matrix is intentionally simple — a dict of dicts — so it serializes
    cleanly to JSON for the ScanResult output.
    """

    # Primary store: endpoint_key -> identity_name -> object_id -> ResponseMeta
    _cells: dict[str, dict[str, dict[str | None, ResponseMeta]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(dict))
    )

    def record(self, meta: ResponseMeta) -> None:
        """
        Store a ResponseMeta in the matrix.

        Args:
            meta: The ResponseMeta from a completed (or errored) request.
        """
        self._cells[meta.endpoint_key][meta.identity_name][meta.object_id_used] = meta

    @property
    def endpoint_keys(self) -> list[str]:
        """All endpoint keys that have at least one recorded response."""
        return list(self._cells.keys())

    def identities_for(self, endpoint_key: str) -> list[str]:
        """Identity names that have responses for a given endpoint."""
        return list(self._cells.get(endpoint_key, {}).keys())

    def get(
        self,
        endpoint_key: str,
        identity_name: str,
        object_id: str | None = None,
    ) -> ResponseMeta | None:
        """
        Retrieve a specific cell from the matrix.

        Args:
            endpoint_key: The endpoint key (e.g. "GET /api/users/{id}").
            identity_name: The identity name (e.g. "alice").
            object_id: The object ID used in the request, or None.

        Returns:
            The ResponseMeta for that cell, or None if not recorded.
        """
        return self._cells.get(endpoint_key, {}).get(identity_name, {}).get(object_id)

    def all_responses_for_endpoint(self, endpoint_key: str) -> list[ResponseMeta]:
        """Return all ResponseMeta recorded for an endpoint, across all identities."""
        results = []
        for identity_cells in self._cells.get(endpoint_key, {}).values():
            results.extend(identity_cells.values())
        return results

    def responses_for_identity(
        self, endpoint_key: str, identity_name: str
    ) -> list[ResponseMeta]:
        """Return all ResponseMeta for a specific (endpoint, identity) pair."""
        return list(
            self._cells.get(endpoint_key, {}).get(identity_name, {}).values()
        )

    def to_status_summary(self) -> dict[str, dict[str, int]]:
        """
        Produce a compact status-code summary for ScanResult.auth_matrix.

        Returns a dict[endpoint_key -> dict[identity_name -> status_code]].
        When multiple object IDs exist, the first non-error status code is used.
        This is the serialized form stored in ScanResult.
        """
        summary: dict[str, dict[str, int]] = {}
        for ep_key, identity_map in self._cells.items():
            summary[ep_key] = {}
            for identity_name, oid_map in identity_map.items():
                # Pick the first non-error status code (status_code > 0)
                for meta in oid_map.values():
                    if meta.status_code > 0:
                        summary[ep_key][identity_name] = meta.status_code
                        break
                else:
                    # All were errors
                    summary[ep_key][identity_name] = 0
        return summary

    @property
    def total_cells(self) -> int:
        """Total number of (endpoint, identity, object_id) cells recorded."""
        return sum(
            len(oid_map)
            for identity_map in self._cells.values()
            for oid_map in identity_map.values()
        )


def build_matrix(responses: list[ResponseMeta]) -> AuthMatrix:
    """
    Build an AuthMatrix from a flat list of ResponseMeta.

    This is called once after the executor finishes. It converts the
    flat list into the indexed structure the detector needs.

    Args:
        responses: All ResponseMeta collected by the executor.

    Returns:
        Populated AuthMatrix.
    """
    matrix = AuthMatrix()
    for meta in responses:
        matrix.record(meta)

    log.info(
        "matrix_built",
        endpoints=len(matrix.endpoint_keys),
        total_cells=matrix.total_cells,
    )
    return matrix
