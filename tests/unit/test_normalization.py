"""
Unit tests for URL and path normalization utilities.
"""

import pytest

from bac_detector.utils.normalization import (
    build_url,
    is_object_id_param,
    normalize_base_url,
    normalize_path,
)


class TestNormalizePath:
    def test_already_templated_passthrough(self):
        assert normalize_path("/api/users/{user_id}") == "/api/users/{user_id}"

    def test_numeric_segment_replaced(self):
        assert normalize_path("/api/users/123") == "/api/users/{id}"

    def test_uuid_segment_replaced(self):
        result = normalize_path("/api/orders/550e8400-e29b-41d4-a716-446655440000")
        assert result == "/api/orders/{id}"

    def test_non_id_segment_preserved(self):
        assert normalize_path("/api/users/profile") == "/api/users/profile"

    def test_multiple_segments(self):
        result = normalize_path("/api/users/42/orders/99")
        assert result == "/api/users/{id}/orders/{id}"

    def test_root_path(self):
        assert normalize_path("/") == "/"

    def test_no_leading_slash_path(self):
        result = normalize_path("api/users/123")
        assert result == "/api/users/{id}"

    # B1 fixes — query strings and fragments
    def test_query_string_stripped_before_normalization(self):
        assert normalize_path("/api/users?page=1") == "/api/users"

    def test_query_string_with_numeric_segment(self):
        # Previously "123?format=json" was not matched as numeric — now it is
        result = normalize_path("/api/users/123?format=json")
        assert result == "/api/users/{id}"

    def test_fragment_stripped(self):
        assert normalize_path("/api/users#section") == "/api/users"

    def test_both_query_and_fragment_stripped(self):
        result = normalize_path("/api/users/42?a=1#top")
        assert result == "/api/users/{id}"

    # Trailing slash handling
    def test_trailing_slash_removed(self):
        assert normalize_path("/api/users/") == "/api/users"

    def test_double_trailing_slash(self):
        # Extra slashes produce empty segments which are skipped
        assert normalize_path("/api/users//") == "/api/users"

    def test_templated_path_with_trailing_slash(self):
        # Already-templated paths pass through before the slash-stripping loop
        result = normalize_path("/api/users/{user_id}/")
        # The path starts with { so it passes through as-is
        assert result == "/api/users/{user_id}/"


class TestNormalizeBaseUrl:
    def test_strips_trailing_slash(self):
        assert normalize_base_url("https://api.example.com/") == "https://api.example.com"

    def test_lowercases_scheme_and_host(self):
        result = normalize_base_url("HTTPS://API.EXAMPLE.COM/v1")
        assert result == "https://api.example.com/v1"

    def test_strips_fragment(self):
        result = normalize_base_url("https://api.example.com/v1#section")
        assert result == "https://api.example.com/v1"

    def test_preserves_path(self):
        result = normalize_base_url("https://api.example.com/v2")
        assert result == "https://api.example.com/v2"


class TestBuildUrl:
    def test_simple_join(self):
        result = build_url("https://api.example.com", "/users/1")
        assert result == "https://api.example.com/users/1"

    def test_base_with_path(self):
        result = build_url("https://api.example.com/v1", "/users/1")
        assert result == "https://api.example.com/v1/users/1"

    def test_path_without_leading_slash(self):
        result = build_url("https://api.example.com/v1", "users/1")
        assert result == "https://api.example.com/v1/users/1"

    def test_base_trailing_slash_handled(self):
        result = build_url("https://api.example.com/v1/", "/users")
        assert result == "https://api.example.com/v1/users"


class TestIsObjectIdParam:
    @pytest.mark.parametrize(
        "name",
        [
            "id", "user_id", "userid", "profile_id", "account_id",
            "order_id", "invoice_id", "tenant_id", "document_id",
            "customer_id", "admin_id", "item_id", "resource_id",
            "record_id", "org_id", "organization_id", "project_id",
        ],
    )
    def test_known_object_id_params(self, name: str):
        assert is_object_id_param(name) is True

    @pytest.mark.parametrize(
        "name",
        ["page", "limit", "format", "sort", "q", "search", "offset", "fields"],
    )
    def test_non_object_id_params(self, name: str):
        assert is_object_id_param(name) is False

    def test_case_insensitive(self):
        assert is_object_id_param("USER_ID") is True
        assert is_object_id_param("Id") is True
