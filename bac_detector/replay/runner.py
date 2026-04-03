"""
Replay runner.

Orchestrates the full replay phase:
  1. Collects all object IDs available across all identities
  2. Builds PreparedRequests for every (endpoint, identity, object_id) triple
  3. Sends them through the executor
  4. Returns all ResponseMeta for the analyzer phase

This is the main entry point called from the CLI scan command.
"""

from __future__ import annotations

import asyncio

from bac_detector.config.loader import ScanConfig
from bac_detector.discovery.inventory import EndpointInventory
from bac_detector.models.endpoint import HttpMethod
from bac_detector.models.identity import IdentityProfile
from bac_detector.models.response_meta import ResponseMeta
from bac_detector.replay.builder import PreparedRequest, build_requests
from bac_detector.replay.executor import ExecutionSummary, ExecutorConfig, execute_requests
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


def run_replay(
    inventory: EndpointInventory,
    config: ScanConfig,
) -> tuple[list[ResponseMeta], ExecutionSummary]:
    """
    Run the full replay phase synchronously (wraps the async implementation).

    Builds requests for every endpoint × identity combination, then
    sends them through the rate-limited async executor.

    Only GET endpoints are tested in MVP. The method filter is applied
    here and in the builder — double-checked for safety.

    Args:
        inventory: The discovered endpoint inventory from Phase 2.
        config: The validated scan configuration.

    Returns:
        Tuple of (all ResponseMeta collected, ExecutionSummary with stats).
    """
    profiles = config.identity_profiles
    executor_cfg = ExecutorConfig(
        requests_per_second=config.throttle.requests_per_second,
        request_budget=config.throttle.request_budget,
        timeout_seconds=config.throttle.timeout_seconds,
        verify_ssl=config.safety.verify_ssl,
        dry_run=config.safety.dry_run,
    )

    log.info(
        "replay_starting",
        endpoints=inventory.total,
        identities=[p.name for p in profiles],
        budget=executor_cfg.request_budget,
        rps=executor_cfg.requests_per_second,
        dry_run=executor_cfg.dry_run,
    )

    # Build the full request list
    all_requests = _build_all_requests(inventory, profiles)

    log.info("replay_requests_built", total=len(all_requests))

    if not all_requests:
        log.warning("replay_no_requests_built")
        return [], ExecutionSummary()

    # Run async executor in a new event loop
    responses, summary = asyncio.run(execute_requests(all_requests, executor_cfg))

    log.info(
        "replay_complete",
        responses=len(responses),
        sent=summary.total_sent,
        errors=summary.total_errors,
        budget_exhausted=summary.budget_exhausted,
    )

    return responses, summary


def _build_all_requests(
    inventory: EndpointInventory,
    profiles: list[IdentityProfile],
) -> list[PreparedRequest]:
    """
    Build PreparedRequests for all GET endpoints × all identities.

    Object ID strategy:
      - Collect all owned_object_ids across all identities into a shared pool
      - For each endpoint with object-ID params, replay with every ID in the pool
      - This allows identity A to be tested against IDs owned by identity B,
        which is the core IDOR detection pattern

    The pool is capped at a reasonable size to keep request counts bounded.

    Args:
        inventory: Endpoint inventory from Phase 2.
        profiles: All configured identity profiles.

    Returns:
        Flat list of PreparedRequest objects.
    """
    object_id_pool = _collect_object_ids(profiles)

    all_requests: list[PreparedRequest] = []

    for endpoint in inventory.endpoints:
        # MVP: GET only
        if endpoint.method != HttpMethod.GET:
            continue

        requests = build_requests(
            endpoint=endpoint,
            identities=profiles,
            object_ids=object_id_pool if endpoint.object_id_params else None,
        )
        all_requests.extend(requests)

    return all_requests


def _collect_object_ids(profiles: list[IdentityProfile]) -> list[str]:
    """
    Collect all owned_object_ids across all identity profiles into one pool.

    Deduplicates and preserves order. Capped at 20 IDs to keep the
    request count bounded even with many identities.

    Args:
        profiles: All configured identity profiles.

    Returns:
        Deduplicated list of object IDs from all identities.
    """
    seen: set[str] = set()
    pool: list[str] = []
    for profile in profiles:
        for oid in profile.owned_object_ids:
            if oid not in seen:
                seen.add(oid)
                pool.append(oid)
    return pool[:20]
