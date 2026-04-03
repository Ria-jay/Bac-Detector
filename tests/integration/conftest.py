"""
Integration test fixtures for Phase 6.

Starts the demo FastAPI app in a background thread before the test session
and shuts it down after. Provides a pre-built ScanConfig that points at it.

The app is bound to a random free port to avoid collisions when tests run
in parallel or alongside other services.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from bac_detector.config.loader import (
    IdentityConfig,
    OutputConfig,
    SafetyConfig,
    ScanConfig,
    TargetConfig,
    ThrottleConfig,
)
from bac_detector.models.identity import AuthMechanism


# ---------------------------------------------------------------------------
# Free-port helper
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    """Return an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Uvicorn server fixture
# ---------------------------------------------------------------------------

class _Server(uvicorn.Server):
    """Uvicorn server that sets a threading.Event when ready."""

    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self._ready = threading.Event()

    def install_signal_handlers(self) -> None:
        # Disable signal handlers so the server works in a non-main thread
        pass

    async def startup(self, sockets=None) -> None:
        await super().startup(sockets=sockets)
        self._ready.set()


@pytest.fixture(scope="session")
def demo_app_url() -> str:
    """
    Start the demo FastAPI app and return its base URL.

    Runs for the entire test session — the server is started once and
    torn down after all integration tests complete.
    """
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(
        "demo_app.app:app",
        host="127.0.0.1",
        port=port,
        log_level="error",   # suppress uvicorn logs during tests
    )
    server = _Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait up to 5 seconds for the server to be ready
    if not server._ready.wait(timeout=5.0):
        raise RuntimeError("Demo app did not start within 5 seconds")

    # Brief extra wait for the socket to be fully accepting connections
    time.sleep(0.1)

    yield base_url

    server.should_exit = True
    thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# ScanConfig fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def demo_scan_config(demo_app_url: str, tmp_path_factory) -> ScanConfig:
    """
    Build a ScanConfig that points the scanner at the running demo app.

    Uses the demo app's built-in OpenAPI spec for discovery.
    Alice and bob are regular users; admin has the admin role.
    owned_object_ids are set so IDOR detection has ownership context.
    """
    output_dir = str(tmp_path_factory.mktemp("scan_output"))

    return ScanConfig(
        target=TargetConfig(
            base_url=demo_app_url,
            openapi_url=f"{demo_app_url}/openapi.json",
        ),
        identities=[
            IdentityConfig(
                name="alice",
                role="user",
                auth_mechanism=AuthMechanism.BEARER,
                token="token-alice",
                owned_object_ids=["1"],   # alice owns user record 1
            ),
            IdentityConfig(
                name="bob",
                role="user",
                auth_mechanism=AuthMechanism.BEARER,
                token="token-bob",
                owned_object_ids=["2"],   # bob owns user record 2
            ),
            IdentityConfig(
                name="admin",
                role="admin",
                auth_mechanism=AuthMechanism.BEARER,
                token="token-admin",
                owned_object_ids=["3"],
            ),
        ],
        throttle=ThrottleConfig(
            requests_per_second=50.0,  # fast for local testing
            request_budget=500,
            timeout_seconds=10.0,
        ),
        safety=SafetyConfig(
            dry_run=False,
            read_only=True,
            verify_ssl=False,
        ),
        output=OutputConfig(
            output_dir=output_dir,
            overwrite=True,
        ),
    )
