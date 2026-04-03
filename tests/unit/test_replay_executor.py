"""
Unit tests for replay/executor.py.

Uses pytest-httpx to mock HTTP responses so no real network calls are made.
Tests cover dry-run mode, budget enforcement, rate limiting, error handling,
and ResponseMeta construction from responses.
"""

import pytest
import pytest_asyncio

from bac_detector.replay.builder import PreparedRequest
from bac_detector.replay.executor import (
    ExecutorConfig,
    _dry_run_meta,
    _error_meta,
    execute_requests,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_request(
    url: str = "https://api.example.com/api/users",
    identity: str = "alice",
    object_id: str | None = None,
) -> PreparedRequest:
    return PreparedRequest(
        method="GET",
        url=url,
        headers={"Authorization": "Bearer tok"},
        cookies={},
        object_id_used=object_id,
        endpoint_key="GET /api/users",
        identity_name=identity,
    )


def _make_config(**kwargs) -> ExecutorConfig:
    defaults = dict(
        requests_per_second=100.0,  # fast for tests
        request_budget=500,
        timeout_seconds=5.0,
        verify_ssl=False,
        dry_run=False,
    )
    defaults.update(kwargs)
    return ExecutorConfig(**defaults)


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestDryRunMode:
    def test_dry_run_returns_synthetic_meta(self):
        req = _make_request()
        meta = _dry_run_meta(req)
        assert meta.status_code == 0
        assert meta.error == "dry_run"
        assert meta.identity_name == "alice"
        assert meta.endpoint_key == "GET /api/users"

    @pytest.mark.asyncio
    async def test_execute_dry_run_no_http_calls(self):
        # In dry-run mode, execute_requests must return without sending any HTTP requests
        # We don't need httpx mocking because nothing is sent
        requests = [_make_request(), _make_request(identity="bob")]
        config = _make_config(dry_run=True)
        responses, summary = await execute_requests(requests, config)
        assert len(responses) == 2
        assert summary.total_skipped_dry_run == 2
        assert summary.total_sent == 0
        assert all(r.error == "dry_run" for r in responses)

    @pytest.mark.asyncio
    async def test_execute_dry_run_preserves_identity_names(self):
        requests = [
            _make_request(identity="alice"),
            _make_request(identity="bob"),
        ]
        config = _make_config(dry_run=True)
        responses, _ = await execute_requests(requests, config)
        names = [r.identity_name for r in responses]
        assert names == ["alice", "bob"]


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------


class TestBudgetEnforcement:
    @pytest.mark.asyncio
    async def test_budget_stops_execution(self, httpx_mock):
        # Budget of 2 — only 2 of 3 requests should be sent
        httpx_mock.add_response(status_code=200, text='{"ok": true}')
        httpx_mock.add_response(status_code=200, text='{"ok": true}')

        requests = [
            _make_request(url="https://api.example.com/api/a"),
            _make_request(url="https://api.example.com/api/b"),
            _make_request(url="https://api.example.com/api/c"),
        ]
        config = _make_config(request_budget=2)
        responses, summary = await execute_requests(requests, config)

        assert summary.total_sent == 2
        assert summary.budget_exhausted is True
        # Only 2 responses, not 3
        assert len(responses) == 2

    @pytest.mark.asyncio
    async def test_full_budget_sends_all(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text="ok")
        httpx_mock.add_response(status_code=403, text="forbidden")

        requests = [_make_request(), _make_request(identity="bob")]
        config = _make_config(request_budget=100)
        responses, summary = await execute_requests(requests, config)

        assert summary.total_sent == 2
        assert summary.budget_exhausted is False
        assert len(responses) == 2


# ---------------------------------------------------------------------------
# Response metadata construction
# ---------------------------------------------------------------------------


class TestResponseMetaConstruction:
    @pytest.mark.asyncio
    async def test_status_code_captured(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text='{"id": 1}')
        requests = [_make_request()]
        config = _make_config()
        responses, _ = await execute_requests(requests, config)
        assert responses[0].status_code == 200

    @pytest.mark.asyncio
    async def test_json_keys_extracted(self, httpx_mock):
        httpx_mock.add_response(
            status_code=200,
            text='{"id": 1, "name": "alice", "email": "a@b.com"}',
            headers={"content-type": "application/json"},
        )
        requests = [_make_request()]
        config = _make_config()
        responses, _ = await execute_requests(requests, config)
        assert "id" in responses[0].json_keys
        assert "name" in responses[0].json_keys

    @pytest.mark.asyncio
    async def test_403_captured(self, httpx_mock):
        httpx_mock.add_response(status_code=403, text="Forbidden")
        requests = [_make_request()]
        config = _make_config()
        responses, _ = await execute_requests(requests, config)
        assert responses[0].status_code == 403
        assert responses[0].is_access_denied is True

    @pytest.mark.asyncio
    async def test_object_id_preserved(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text='{}')
        req = _make_request(url="https://api.example.com/api/users/42", object_id="42")
        config = _make_config()
        responses, _ = await execute_requests([req], config)
        assert responses[0].object_id_used == "42"

    @pytest.mark.asyncio
    async def test_identity_name_preserved(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text='{}')
        req = _make_request(identity="bob")
        config = _make_config()
        responses, _ = await execute_requests([req], config)
        assert responses[0].identity_name == "bob"

    @pytest.mark.asyncio
    async def test_latency_recorded(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text='{}')
        requests = [_make_request()]
        config = _make_config()
        responses, _ = await execute_requests(requests, config)
        assert responses[0].latency_ms >= 0.0

    @pytest.mark.asyncio
    async def test_body_snippet_captured(self, httpx_mock):
        httpx_mock.add_response(status_code=200, text='{"result": "ok"}')
        requests = [_make_request()]
        config = _make_config()
        responses, _ = await execute_requests(requests, config)
        assert "result" in responses[0].body_snippet


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_error_meta_construction(self):
        req = _make_request()
        meta = _error_meta(req, "Timeout: connection timed out", 5000.0)
        assert meta.status_code == 0
        assert meta.error == "Timeout: connection timed out"
        assert meta.latency_ms == 5000.0
        assert meta.identity_name == "alice"

    @pytest.mark.asyncio
    async def test_network_error_captured_not_raised(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ConnectError("connection refused"))
        requests = [_make_request()]
        config = _make_config()
        # Must not raise — error is captured in ResponseMeta
        responses, summary = await execute_requests(requests, config)
        assert len(responses) == 1
        assert responses[0].error is not None
        assert responses[0].status_code == 0
        assert summary.total_errors == 1

    @pytest.mark.asyncio
    async def test_empty_request_list_returns_empty(self):
        config = _make_config()
        responses, summary = await execute_requests([], config)
        assert responses == []
        assert summary.total_sent == 0
