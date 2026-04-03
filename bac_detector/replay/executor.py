"""
Async request executor with rate limiting and budget control.

The executor is the only place in BAC Detector that sends HTTP requests.
All safety controls — dry-run mode, request budget, rate limiting,
SSL verification — are enforced here.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

from bac_detector.models.response_meta import ResponseMeta
from bac_detector.replay.builder import PreparedRequest
from bac_detector.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class ExecutorConfig:
    """
    Runtime configuration for the executor.

    Copied from ScanConfig so the executor has no direct dependency
    on the config module (keeps the dependency graph clean).
    """

    requests_per_second: float = 2.0
    request_budget: int = 500
    timeout_seconds: float = 15.0
    verify_ssl: bool = True
    dry_run: bool = False


@dataclass
class ExecutionSummary:
    """
    Stats collected across a full replay run.

    Returned alongside the response list so callers can log or
    surface the budget/rate numbers without re-computing them.
    """

    total_sent: int = 0
    total_skipped_dry_run: int = 0
    total_errors: int = 0
    budget_exhausted: bool = False
    elapsed_seconds: float = 0.0


@dataclass
class _RateLimiter:
    """
    Token-bucket rate limiter.

    Ensures we never send more than `requests_per_second` on average.
    Simple and predictable — no bursty behaviour.
    """

    requests_per_second: float
    _last_request_time: float = field(default_factory=time.monotonic, init=False)

    async def acquire(self) -> None:
        """Wait until the next request slot is available."""
        min_interval = 1.0 / self.requests_per_second
        now = time.monotonic()
        elapsed = now - self._last_request_time
        wait = min_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_time = time.monotonic()


async def execute_requests(
    requests: list[PreparedRequest],
    config: ExecutorConfig,
) -> tuple[list[ResponseMeta], ExecutionSummary]:
    """
    Send a list of PreparedRequests and return ResponseMeta for each.

    Enforces:
      - dry-run mode (logs requests, returns synthetic 0-status metadata)
      - request budget (stops when budget is exhausted)
      - per-request rate limiting
      - per-request timeout
      - SSL verification toggle

    Args:
        requests: Ordered list of PreparedRequests to send.
        config: Executor configuration.

    Returns:
        Tuple of (list of ResponseMeta, ExecutionSummary).
        The ResponseMeta list is in the same order as the input requests,
        with error entries for any failed requests.
    """
    summary = ExecutionSummary()
    results: list[ResponseMeta] = []
    start_time = time.monotonic()
    rate_limiter = _RateLimiter(requests_per_second=config.requests_per_second)

    if config.dry_run:
        log.info("executor_dry_run_mode", total_requests=len(requests))
        for req in requests:
            log.info(
                "dry_run_request",
                method=req.method,
                url=req.url,
                identity=req.identity_name,
                object_id=req.object_id_used,
            )
            results.append(_dry_run_meta(req))
            summary.total_skipped_dry_run += 1
        summary.elapsed_seconds = time.monotonic() - start_time
        return results, summary

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.timeout_seconds),
        follow_redirects=True,
        verify=config.verify_ssl,
        headers={
            "User-Agent": "BACDetector/0.1.0 (authorized-security-testing)",
            "Accept": "application/json, */*",
        },
    ) as client:
        for req in requests:
            if summary.total_sent >= config.request_budget:
                log.warning(
                    "executor_budget_exhausted",
                    budget=config.request_budget,
                    sent=summary.total_sent,
                )
                summary.budget_exhausted = True
                break

            await rate_limiter.acquire()

            meta = await _send_one(client, req)
            results.append(meta)

            if meta.error:
                summary.total_errors += 1
            else:
                summary.total_sent += 1

            log.debug(
                "request_sent",
                method=req.method,
                url=req.url,
                identity=req.identity_name,
                status=meta.status_code,
                latency_ms=round(meta.latency_ms, 1),
                object_id=req.object_id_used,
            )

    summary.elapsed_seconds = time.monotonic() - start_time
    log.info(
        "executor_complete",
        sent=summary.total_sent,
        errors=summary.total_errors,
        budget_exhausted=summary.budget_exhausted,
        elapsed_s=round(summary.elapsed_seconds, 2),
    )
    return results, summary


async def _send_one(
    client: httpx.AsyncClient,
    req: PreparedRequest,
) -> ResponseMeta:
    """
    Send a single PreparedRequest and return a ResponseMeta.

    Never raises — network and HTTP errors are captured in ResponseMeta.error.

    Args:
        client: The shared httpx.AsyncClient.
        req: The request to send.

    Returns:
        ResponseMeta capturing the response (or error).
    """
    t_start = time.monotonic()
    try:
        response = await client.request(
            method=req.method,
            url=req.url,
            headers=req.headers,
            cookies=req.cookies,
        )
        latency_ms = (time.monotonic() - t_start) * 1000.0

        # Decode body safely — non-UTF-8 bodies get replacement chars
        try:
            body = response.text
        except Exception:
            body = response.content.decode("utf-8", errors="replace")

        content_type = response.headers.get("content-type")

        return ResponseMeta.from_response(
            status_code=response.status_code,
            body=body,
            content_type=content_type,
            latency_ms=latency_ms,
            endpoint_key=req.endpoint_key,
            identity_name=req.identity_name,
            requested_url=req.url,
            object_id_used=req.object_id_used,
        )

    except httpx.TimeoutException as exc:
        latency_ms = (time.monotonic() - t_start) * 1000.0
        log.warning("request_timeout", url=req.url, identity=req.identity_name)
        return _error_meta(req, f"Timeout: {exc}", latency_ms)

    except httpx.RequestError as exc:
        latency_ms = (time.monotonic() - t_start) * 1000.0
        log.warning("request_error", url=req.url, identity=req.identity_name, error=str(exc))
        return _error_meta(req, f"Request error: {exc}", latency_ms)


def _dry_run_meta(req: PreparedRequest) -> ResponseMeta:
    """Return a synthetic ResponseMeta for dry-run mode (no request sent)."""
    return ResponseMeta(
        status_code=0,
        body_hash="dry_run",
        body_length=0,
        body_snippet="[DRY RUN — request not sent]",
        content_type=None,
        json_keys=[],
        latency_ms=0.0,
        endpoint_key=req.endpoint_key,
        identity_name=req.identity_name,
        requested_url=req.url,
        object_id_used=req.object_id_used,
        error="dry_run",
    )


def _error_meta(req: PreparedRequest, error: str, latency_ms: float) -> ResponseMeta:
    """Return a ResponseMeta representing a failed request."""
    return ResponseMeta(
        status_code=0,
        body_hash="error",
        body_length=0,
        body_snippet="",
        content_type=None,
        json_keys=[],
        latency_ms=latency_ms,
        endpoint_key=req.endpoint_key,
        identity_name=req.identity_name,
        requested_url=req.url,
        object_id_used=req.object_id_used,
        error=error,
    )
