"""
Endpoint inventory builder.

Receives raw Endpoint lists from one or more discovery sources and
produces a clean, deduplicated EndpointInventory.

Deduplication key: (method, normalized_path)
When the same endpoint is found in multiple sources, the higher-priority
source wins (openapi > endpoint_list > js > crawl), but all source
attributions are recorded.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from bac_detector.discovery.endpoint_list import _infer_path_parameters
from bac_detector.models.endpoint import DiscoverySource, Endpoint
from bac_detector.utils.logging import get_logger
from bac_detector.utils.normalization import normalize_path

log = get_logger(__name__)

# Source priority for deduplication: lower number = higher priority
_SOURCE_PRIORITY: dict[str, int] = {
    "openapi": 0,
    "endpoint_list": 1,
    "js": 2,
    "crawl": 3,
}


@dataclass
class EndpointInventory:
    """
    The normalized, deduplicated set of endpoints discovered during a scan.

    Attributes:
        endpoints: Final list of unique Endpoint objects.
        source_counts: How many raw endpoints each source contributed.
        duplicate_count: How many duplicates were dropped during deduplication.
        sources_used: Which discovery sources produced at least one endpoint.
    """

    endpoints: list[Endpoint] = field(default_factory=list)
    source_counts: dict[str, int] = field(default_factory=dict)
    duplicate_count: int = 0
    sources_used: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total number of unique endpoints in the inventory."""
        return len(self.endpoints)

    @property
    def object_id_endpoint_count(self) -> int:
        """Count of endpoints that have at least one likely object-ID parameter."""
        return sum(1 for ep in self.endpoints if ep.object_id_params)

    def filter_by_method(self, method: str) -> list[Endpoint]:
        """Return endpoints matching a specific HTTP method."""
        return [ep for ep in self.endpoints if ep.method.value == method.upper()]

    def filter_by_source(self, source: DiscoverySource) -> list[Endpoint]:
        """Return endpoints that came from a specific discovery source."""
        return [ep for ep in self.endpoints if ep.source == source]

    def summary_lines(self) -> list[str]:
        """Return human-readable summary lines for terminal display."""
        lines = [
            f"Total endpoints:    {self.total}",
            f"Sources used:       {', '.join(self.sources_used) or 'none'}",
            f"Duplicates dropped: {self.duplicate_count}",
        ]
        for source, count in sorted(self.source_counts.items()):
            lines.append(f"  {source:<16} {count} endpoints")
        lines.append(
            f"With object IDs:    {self.object_id_endpoint_count} endpoints "
            f"(IDOR/BOLA candidates)"
        )
        return lines


def build_inventory(endpoint_batches: list[list[Endpoint]]) -> EndpointInventory:
    """
    Build a deduplicated EndpointInventory from one or more endpoint lists.

    Each batch in endpoint_batches comes from a separate discovery source.
    All batches are merged, and duplicates are dropped using source priority.

    Args:
        endpoint_batches: One list per discovery source. Order does not matter —
                          priority is determined by the source field on each endpoint.

    Returns:
        Populated EndpointInventory.
    """
    all_endpoints: list[Endpoint] = [ep for batch in endpoint_batches for ep in batch]

    # Count raw contributions per source before deduplication
    source_counts: dict[str, int] = defaultdict(int)
    for ep in all_endpoints:
        source_counts[ep.source] += 1

    deduplicated, duplicate_count = _deduplicate(all_endpoints)
    sources_used = sorted(
        {ep.source for ep in deduplicated},
        key=lambda s: _SOURCE_PRIORITY.get(s, 99),
    )

    log.info(
        "inventory_built",
        total=len(deduplicated),
        duplicates_dropped=duplicate_count,
        sources=sources_used,
    )

    return EndpointInventory(
        endpoints=deduplicated,
        source_counts=dict(source_counts),
        duplicate_count=duplicate_count,
        sources_used=sources_used,
    )


def _rebuild_endpoint(ep: Endpoint, normalized_path: str) -> Endpoint:
    """
    Rebuild an Endpoint with a normalized path, re-inferring path parameters.

    When a concrete path like /api/users/123 is normalized to /api/users/{id},
    the original endpoint carries no path parameters (because the concrete path
    had no {braces}). This function re-infers parameters from the new templated
    path so that IDOR candidates are not missed.

    If the endpoint already came from OpenAPI, its parameters are preserved as-is
    since OpenAPI provides richer parameter metadata than inference can produce.

    Args:
        ep: The original Endpoint object.
        normalized_path: The normalized path template (e.g. /api/users/{id}).

    Returns:
        A new Endpoint with the corrected path and parameters.
    """
    if ep.source == "openapi":
        # OpenAPI endpoints already have full parameter metadata — preserve it
        params = list(ep.parameters)
    else:
        # For endpoint_list (and future js/crawl sources), re-infer path params
        # from the normalized template, then merge with any existing non-path params
        inferred = _infer_path_parameters(normalized_path)
        inferred_names = {p.name for p in inferred}
        # Keep existing params that are NOT path params (e.g. query params added manually)
        existing_non_path = [
            p for p in ep.parameters
            if p.name not in inferred_names
        ]
        params = inferred + existing_non_path

    return Endpoint(
        method=ep.method,
        path=normalized_path,
        base_url=ep.base_url,
        parameters=params,
        source=ep.source,
        tags=ep.tags,
        summary=ep.summary,
    )


def _deduplicate(endpoints: list[Endpoint]) -> tuple[list[Endpoint], int]:
    """
    Deduplicate endpoints by (method, normalized_path).

    When two endpoints share the same key, the one from the higher-priority
    source is kept. If sources are equal priority, the first-seen is kept.

    Paths are normalized before keying, and any endpoint whose path changes
    during normalization is rebuilt with re-inferred parameters (B2 fix).

    Returns:
        Tuple of (deduplicated list, number of duplicates dropped).
    """
    # key -> (endpoint, priority)
    seen: dict[str, tuple[Endpoint, int]] = {}

    for ep in endpoints:
        normalized = normalize_path(ep.path)
        key = f"{ep.method.value} {normalized}"
        priority = _SOURCE_PRIORITY.get(ep.source, 99)

        # Rebuild if normalization changed the path (re-infers parameters)
        if normalized != ep.path:
            ep = _rebuild_endpoint(ep, normalized)

        if key not in seen:
            seen[key] = (ep, priority)
        else:
            existing_priority = seen[key][1]
            if priority < existing_priority:
                # Higher-priority source replaces the existing entry
                seen[key] = (ep, priority)
            # else: existing source has equal or higher priority — keep it

    deduplicated = [ep for ep, _ in seen.values()]
    duplicate_count = len(endpoints) - len(deduplicated)
    return deduplicated, duplicate_count
