"""
Unit tests for auth/profiles.py.

Tests cover header and cookie construction for all auth mechanisms.
These tests moved here from test_models.py when auth logic was
consolidated into auth/profiles.py as the single source of truth.
"""


from bac_detector.auth.profiles import build_request_cookies, build_request_headers
from bac_detector.models.identity import AuthMechanism, IdentityProfile


def _make_identity(**kwargs) -> IdentityProfile:
    defaults = {"name": "alice", "role": "user"}
    defaults.update(kwargs)
    return IdentityProfile(**defaults)


class TestBuildRequestHeaders:
    def test_bearer_sets_authorization_header(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.BEARER,
            token="eyJtest",
        )
        headers = build_request_headers(identity)
        assert headers["Authorization"] == "Bearer eyJtest"

    def test_bearer_no_token_produces_no_auth_header(self):
        # IdentityConfig validator catches this before runtime, but
        # IdentityProfile itself allows it — test the auth function handles it
        identity = IdentityProfile(
            name="broken",
            role="user",
            auth_mechanism=AuthMechanism.BEARER,
            token=None,
        )
        headers = build_request_headers(identity)
        assert "Authorization" not in headers

    def test_cookie_mechanism_no_authorization_header(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.COOKIE,
            cookies={"session": "abc123"},
        )
        headers = build_request_headers(identity)
        assert "Authorization" not in headers

    def test_header_mechanism_custom_headers_included(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.HEADER,
            custom_headers={"X-API-Key": "secret", "X-Tenant": "acme"},
        )
        headers = build_request_headers(identity)
        assert headers["X-API-Key"] == "secret"
        assert headers["X-Tenant"] == "acme"

    def test_none_mechanism_empty_headers(self):
        identity = _make_identity(auth_mechanism=AuthMechanism.NONE)
        headers = build_request_headers(identity)
        assert headers == {}

    def test_bearer_custom_headers_also_included(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.BEARER,
            token="tok123",
            custom_headers={"X-Request-ID": "req-1"},
        )
        headers = build_request_headers(identity)
        assert headers["Authorization"] == "Bearer tok123"
        assert headers["X-Request-ID"] == "req-1"

    def test_returns_new_dict_each_call(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.BEARER,
            token="tok",
        )
        h1 = build_request_headers(identity)
        h2 = build_request_headers(identity)
        assert h1 == h2
        assert h1 is not h2  # independent dicts — mutations don't bleed across calls


class TestBuildRequestCookies:
    def test_cookie_mechanism_returns_cookies(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.COOKIE,
            cookies={"session": "abc123", "csrf": "xyz"},
        )
        cookies = build_request_cookies(identity)
        assert cookies == {"session": "abc123", "csrf": "xyz"}

    def test_bearer_mechanism_returns_empty(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.BEARER,
            token="tok",
        )
        assert build_request_cookies(identity) == {}

    def test_none_mechanism_returns_empty(self):
        identity = _make_identity(auth_mechanism=AuthMechanism.NONE)
        assert build_request_cookies(identity) == {}

    def test_header_mechanism_returns_empty(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.HEADER,
            custom_headers={"X-Key": "val"},
        )
        assert build_request_cookies(identity) == {}

    def test_returns_copy_not_original(self):
        identity = _make_identity(
            auth_mechanism=AuthMechanism.COOKIE,
            cookies={"session": "abc"},
        )
        cookies = build_request_cookies(identity)
        cookies["injected"] = "bad"
        # The identity's cookies dict should not be mutated
        assert "injected" not in build_request_cookies(identity)
