"""
Discovery runner.

Orchestrates all configured discovery sources (OpenAPI, endpoint list)
into a single EndpointInventory. This is the main entry point for
the discovery phase of the pipeline.

Designed to be called from both the `bacdet scan` and `bacdet discover`
CLI commands.
"""

from __future__ import annotations

from bac_detector.config.loader import ScanConfig
from bac_detector.discovery.endpoint_list import parse_endpoint_list
from bac_detector.discovery.inventory import EndpointInventory, build_inventory
from bac_detector.discovery.openapi_parser import parse_openapi
from bac_detector.models.endpoint import Endpoint
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


def run_discovery(config: ScanConfig) -> EndpointInventory:
    """
    Run all configured discovery sources and return a merged EndpointInventory.

    Discovery order (all sources that are configured are run):
        1. OpenAPI / Swagger spec (if target.openapi_url is set)
        2. Explicit endpoint list (if target.endpoint_list_path is set)

    Crawl and JS extraction are post-MVP and are skipped with a log notice
    even if crawl.enabled is True.

    Args:
        config: Validated ScanConfig.

    Returns:
        EndpointInventory containing all unique discovered endpoints.
    """
    base_url = config.effective_api_base_url
    batches: list[list[Endpoint]] = []
    sources_attempted: list[str] = []

    # --- Source 1: OpenAPI / Swagger ---
    if config.target.openapi_url:
        sources_attempted.append("openapi")
        log.info("discovery_source_openapi", url=config.target.openapi_url)
        try:
            openapi_endpoints = parse_openapi(config.target.openapi_url, base_url)
            batches.append(openapi_endpoints)
            log.info(
                "discovery_source_openapi_done",
                count=len(openapi_endpoints),
            )
        except (FileNotFoundError, ValueError) as exc:
            log.error("discovery_source_openapi_failed", error=str(exc))
            raise

    # --- Source 2: Explicit endpoint list ---
    if config.target.endpoint_list_path:
        sources_attempted.append("endpoint_list")
        log.info(
            "discovery_source_endpoint_list",
            path=config.target.endpoint_list_path,
        )
        try:
            list_endpoints = parse_endpoint_list(
                config.target.endpoint_list_path, base_url
            )
            batches.append(list_endpoints)
            log.info(
                "discovery_source_endpoint_list_done",
                count=len(list_endpoints),
            )
        except (FileNotFoundError, ValueError) as exc:
            log.error("discovery_source_endpoint_list_failed", error=str(exc))
            raise

    # --- Source 3: HTML crawl (post-MVP) ---
    if config.crawl.enabled:
        log.info(
            "discovery_source_crawl_skipped",
            reason="HTML crawling is not yet implemented (Phase 7)",
        )

    if not batches:
        raise ValueError(
            "No endpoints discovered. Check that at least one discovery source "
            "is reachable and correctly configured."
        )

    inventory = build_inventory(batches)

    log.info(
        "discovery_complete",
        total_endpoints=inventory.total,
        sources=inventory.sources_used,
        duplicates_dropped=inventory.duplicate_count,
        idor_candidates=inventory.object_id_endpoint_count,
    )

    return inventory
