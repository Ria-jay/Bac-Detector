"""
Unit tests for replay/builder.py.

Tests cover PreparedRequest construction, URL resolution, object ID
substitution, identity auth wiring, and the GET-only filter.
"""


from bac_detector.models.endpoint import Endpoint, HttpMethod, Parameter, ParameterLocation
from bac_detector.models.identity import AuthMechanism, IdentityProfile
from bac_detector.replay.builder import (
    _resolve_url,
    build_requests,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_endpoint(
    method: str = "GET",
    path: str = "/api/users",
    params: list | None = None,
) -> Endpoint:
    return Endpoint(
        method=HttpMethod(method),
        path=path,
        base_url="https://api.example.com",
        parameters=params or [],
        source="openapi",
    )


def _make_id_param(name: str = "user_id") -> Parameter:
    return Parameter(
        name=name,
        location=ParameterLocation.PATH,
        likely_object_id=True,
        required=True,
    )


def _make_identity(
    name: str = "alice",
    mechanism: AuthMechanism = AuthMechanism.BEARER,
    token: str | None = "tok_alice",
    owned_ids: list[str] | None = None,
) -> IdentityProfile:
    return IdentityProfile(
        name=name,
        role="user",
        auth_mechanism=mechanism,
        token=token,
        owned_object_ids=owned_ids or [],
    )


# ---------------------------------------------------------------------------
# _resolve_url
# ---------------------------------------------------------------------------


class TestResolveUrl:
    def test_plain_path_no_substitution(self):
        ep = _make_endpoint(path="/api/users")
        assert _resolve_url(ep, None) == "https://api.example.com/api/users"

    def test_object_id_substituted_in_named_placeholder(self):
        ep = _make_endpoint(
            path="/api/users/{user_id}",
            params=[_make_id_param("user_id")],
        )
        url = _resolve_url(ep, "42")
        assert url == "https://api.example.com/api/users/42"

    def test_generic_id_placeholder_substituted(self):
        ep = _make_endpoint(
            path="/api/users/{id}",
            params=[_make_id_param("id")],
        )
        url = _resolve_url(ep, "99")
        assert url == "https://api.example.com/api/users/99"

    def test_no_object_id_leaves_template(self):
        ep = _make_endpoint(
            path="/api/users/{user_id}",
            params=[_make_id_param("user_id")],
        )
        url = _resolve_url(ep, None)
        # Template left unresolved when no object_id provided
        assert "{user_id}" in url

    def test_base_url_trailing_slash_stripped(self):
        ep = Endpoint(
            method=HttpMethod.GET,
            path="/api/users",
            base_url="https://api.example.com/",
            parameters=[],
            source="openapi",
        )
        url = _resolve_url(ep, None)
        assert not url.startswith("https://api.example.com//")
        assert url == "https://api.example.com/api/users"

    def test_non_id_placeholders_untouched(self):
        # /api/{version}/users — version is not an object ID param
        ep = _make_endpoint(path="/api/{version}/users")
        url = _resolve_url(ep, "42")
        # No object-ID params, so nothing is substituted
        assert "{version}" in url


# ---------------------------------------------------------------------------
# build_requests — basic cases
# ---------------------------------------------------------------------------


class TestBuildRequests:
    def test_get_endpoint_one_request_per_identity(self):
        ep = _make_endpoint("GET", "/api/users")
        identities = [_make_identity("alice"), _make_identity("bob", token="tok_bob")]
        requests = build_requests(ep, identities)
        assert len(requests) == 2
        names = {r.identity_name for r in requests}
        assert names == {"alice", "bob"}

    def test_non_get_endpoint_returns_empty(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            ep = _make_endpoint(method, "/api/users")
            result = build_requests(ep, [_make_identity()])
            assert result == [], f"Expected empty list for {method}"

    def test_all_requests_are_get(self):
        ep = _make_endpoint("GET", "/api/users")
        requests = build_requests(ep, [_make_identity()])
        assert all(r.method == "GET" for r in requests)

    def test_endpoint_key_set_correctly(self):
        ep = _make_endpoint("GET", "/api/users")
        requests = build_requests(ep, [_make_identity()])
        assert all(r.endpoint_key == "GET /api/users" for r in requests)

    def test_identity_name_set_correctly(self):
        ep = _make_endpoint("GET", "/api/users")
        identities = [_make_identity("alice"), _make_identity("bob", token="tok_bob")]
        requests = build_requests(ep, identities)
        assert {r.identity_name for r in requests} == {"alice", "bob"}

    def test_object_ids_produce_cross_product(self):
        ep = _make_endpoint(
            "GET", "/api/users/{user_id}",
            params=[_make_id_param("user_id")],
        )
        identities = [_make_identity("alice"), _make_identity("bob", token="tok_bob")]
        requests = build_requests(ep, identities, object_ids=["1", "2"])
        # 2 identities × 2 object_ids = 4 requests
        assert len(requests) == 4

    def test_object_id_substituted_in_url(self):
        ep = _make_endpoint(
            "GET", "/api/users/{user_id}",
            params=[_make_id_param("user_id")],
        )
        requests = build_requests(ep, [_make_identity()], object_ids=["42"])
        assert requests[0].url == "https://api.example.com/api/users/42"
        assert requests[0].object_id_used == "42"

    def test_no_object_ids_no_id_params_returns_one_per_identity(self):
        # Endpoint has no object-ID params and no IDs provided
        ep = _make_endpoint("GET", "/api/health")
        requests = build_requests(ep, [_make_identity()])
        assert len(requests) == 1
        assert requests[0].object_id_used is None


# ---------------------------------------------------------------------------
# Auth wiring
# ---------------------------------------------------------------------------


class TestAuthWiring:
    def test_bearer_token_in_headers(self):
        ep = _make_endpoint()
        identity = _make_identity(mechanism=AuthMechanism.BEARER, token="my_token")
        requests = build_requests(ep, [identity])
        assert requests[0].headers.get("Authorization") == "Bearer my_token"

    def test_cookie_identity_has_no_auth_header(self):
        ep = _make_endpoint()
        identity = IdentityProfile(
            name="carol",
            role="user",
            auth_mechanism=AuthMechanism.COOKIE,
            cookies={"session": "abc123"},
        )
        requests = build_requests(ep, [identity])
        assert "Authorization" not in requests[0].headers
        assert requests[0].cookies == {"session": "abc123"}

    def test_none_identity_no_auth(self):
        ep = _make_endpoint()
        identity = IdentityProfile(
            name="guest",
            role="guest",
            auth_mechanism=AuthMechanism.NONE,
        )
        requests = build_requests(ep, [identity])
        assert "Authorization" not in requests[0].headers
        assert requests[0].cookies == {}

    def test_custom_headers_included(self):
        ep = _make_endpoint()
        identity = IdentityProfile(
            name="service",
            role="user",
            auth_mechanism=AuthMechanism.HEADER,
            custom_headers={"X-API-Key": "secret"},
        )
        requests = build_requests(ep, [identity])
        assert requests[0].headers.get("X-API-Key") == "secret"
