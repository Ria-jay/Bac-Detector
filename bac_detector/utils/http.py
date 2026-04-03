"""
Shared httpx client factory.

Provides a configured async HTTP client used by the replay engine.
All HTTP communication in BAC Detector goes through this client.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx


def build_client(
    timeout: float = 15.0,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    """
    Build a configured httpx.AsyncClient.

    Args:
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.
        verify_ssl: Whether to verify TLS certificates.
        headers: Default headers to include in every request.

    Returns:
        Configured httpx.AsyncClient instance.
    """
    default_headers = {
        "User-Agent": "BACDetector/0.1.0 (authorized-security-testing)",
        "Accept": "application/json, */*",
    }
    if headers:
        default_headers.update(headers)

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        verify=verify_ssl,
        headers=default_headers,
    )


@asynccontextmanager
async def managed_client(
    timeout: float = 15.0,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    headers: dict[str, str] | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    """
    Context manager that yields a configured httpx.AsyncClient and ensures cleanup.

    Usage:
        async with managed_client() as client:
            response = await client.get("https://api.example.com/users")

    Args:
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.
        verify_ssl: Whether to verify TLS certificates.
        headers: Default headers to include in every request.
    """
    client = build_client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify_ssl=verify_ssl,
        headers=headers,
    )
    try:
        yield client
    finally:
        await client.aclose()
