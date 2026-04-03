"""
Unit tests for the explicit endpoint list parser.

Tests cover valid formats, alternative param styles, comment/blank line
handling, deduplication, and error cases.
"""

from pathlib import Path

import pytest

from bac_detector.discovery.endpoint_list import (
    parse_endpoint_list,
    parse_endpoint_list_text,
    _normalise_param_styles,
    _infer_path_parameters,
    _parse_line,
)
from bac_detector.models.endpoint import HttpMethod, ParameterLocation

BASE_URL = "https://api.example.com"


# ---------------------------------------------------------------------------
# _normalise_param_styles
# ---------------------------------------------------------------------------


class TestNormaliseParamStyles:
    def test_colon_style_converted(self):
        result = _normalise_param_styles("GET /api/users/:user_id")
        assert result == "GET /api/users/{user_id}"

    def test_bracket_style_converted(self):
        result = _normalise_param_styles("GET /api/docs/[doc_id]")
        assert result == "GET /api/docs/{doc_id}"

    def test_brace_style_unchanged(self):
        result = _normalise_param_styles("GET /api/users/{user_id}")
        assert result == "GET /api/users/{user_id}"

    def test_multiple_colon_params(self):
        result = _normalise_param_styles("GET /api/users/:user_id/orders/:order_id")
        assert result == "GET /api/users/{user_id}/orders/{order_id}"

    def test_no_params_unchanged(self):
        result = _normalise_param_styles("GET /api/users")
        assert result == "GET /api/users"


# ---------------------------------------------------------------------------
# _infer_path_parameters
# ---------------------------------------------------------------------------


class TestInferPathParameters:
    def test_no_params(self):
        params = _infer_path_parameters("/api/users")
        assert params == []

    def test_single_param(self):
        params = _infer_path_parameters("/api/users/{user_id}")
        assert len(params) == 1
        p = params[0]
        assert p.name == "user_id"
        assert p.location == ParameterLocation.PATH
        assert p.likely_object_id is True
        assert p.required is True

    def test_multiple_params(self):
        params = _infer_path_parameters("/api/users/{user_id}/orders/{order_id}")
        assert len(params) == 2
        names = {p.name for p in params}
        assert names == {"user_id", "order_id"}

    def test_non_id_param_not_flagged(self):
        params = _infer_path_parameters("/api/{version}/resource")
        assert len(params) == 1
        assert params[0].likely_object_id is False


# ---------------------------------------------------------------------------
# parse_endpoint_list_text — in-memory parsing
# ---------------------------------------------------------------------------


class TestParseEndpointListText:
    def test_simple_get(self):
        endpoints = parse_endpoint_list_text("GET /api/users", BASE_URL)
        assert len(endpoints) == 1
        assert endpoints[0].method == HttpMethod.GET
        assert endpoints[0].path == "/api/users"

    def test_default_method_is_get(self):
        endpoints = parse_endpoint_list_text("/api/users", BASE_URL)
        assert len(endpoints) == 1
        assert endpoints[0].method == HttpMethod.GET

    def test_multiple_methods(self):
        text = """
GET  /api/users
POST /api/users
GET  /api/users/{user_id}
PUT  /api/users/{user_id}
DELETE /api/users/{user_id}
"""
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert len(endpoints) == 5

    def test_comments_ignored(self):
        text = """
# This is a comment
GET /api/users
# Another comment
GET /api/orders
"""
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert len(endpoints) == 2

    def test_blank_lines_ignored(self):
        text = "\n\nGET /api/users\n\n\nGET /api/orders\n\n"
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert len(endpoints) == 2

    def test_deduplication_within_file(self):
        text = "GET /api/users\nGET /api/users\nGET /api/users"
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert len(endpoints) == 1

    def test_source_is_endpoint_list(self):
        endpoints = parse_endpoint_list_text("GET /api/test", BASE_URL)
        assert endpoints[0].source == "endpoint_list"

    def test_base_url_attached(self):
        endpoints = parse_endpoint_list_text("GET /api/test", BASE_URL)
        assert endpoints[0].base_url == BASE_URL

    def test_path_params_inferred(self):
        endpoints = parse_endpoint_list_text(
            "GET /api/users/{user_id}/orders/{order_id}", BASE_URL
        )
        params = endpoints[0].parameters
        assert len(params) == 2
        param_names = {p.name for p in params}
        assert param_names == {"user_id", "order_id"}

    def test_colon_style_params_normalised(self):
        endpoints = parse_endpoint_list_text("GET /api/users/:user_id", BASE_URL)
        assert endpoints[0].path == "/api/users/{user_id}"
        assert len(endpoints[0].parameters) == 1

    def test_bracket_style_params_normalised(self):
        endpoints = parse_endpoint_list_text("GET /api/docs/[doc_id]", BASE_URL)
        assert endpoints[0].path == "/api/docs/{doc_id}"

    def test_case_insensitive_method(self):
        endpoints = parse_endpoint_list_text("get /api/users", BASE_URL)
        assert endpoints[0].method == HttpMethod.GET

    def test_unknown_method_skipped(self):
        text = "INVALID /api/bad\nGET /api/good"
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        # The invalid line is skipped; the valid line is kept
        assert len(endpoints) == 1
        assert endpoints[0].path == "/api/good"

    def test_all_supported_methods(self):
        text = "\n".join(
            f"{method} /api/resource"
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        )
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert len(endpoints) == 7

    def test_path_leading_slash_enforced(self):
        endpoints = parse_endpoint_list_text("GET api/no-slash", BASE_URL)
        # path without leading slash won't match regex — treated as bad line
        assert len(endpoints) == 0

    def test_empty_input_returns_empty(self):
        endpoints = parse_endpoint_list_text("", BASE_URL)
        assert endpoints == []

    def test_only_comments_returns_empty(self):
        text = "# just comments\n# no real endpoints"
        endpoints = parse_endpoint_list_text(text, BASE_URL)
        assert endpoints == []

    def test_whitespace_around_method_and_path(self):
        endpoints = parse_endpoint_list_text("  GET   /api/users  ", BASE_URL)
        assert len(endpoints) == 1
        assert endpoints[0].path == "/api/users"


# ---------------------------------------------------------------------------
# parse_endpoint_list — file-based tests
# ---------------------------------------------------------------------------


class TestParseEndpointListFile:
    def test_reads_file(self, tmp_path: Path):
        content = "GET /api/users\nGET /api/orders/{order_id}\n"
        f = tmp_path / "endpoints.txt"
        f.write_text(content)
        endpoints = parse_endpoint_list(str(f), BASE_URL)
        assert len(endpoints) == 2

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_endpoint_list(str(tmp_path / "missing.txt"), BASE_URL)

    def test_uses_sample_endpoints_file(self):
        sample = Path("example/endpoints.txt")
        if not sample.exists():
            pytest.skip("example/endpoints.txt not present")
        endpoints = parse_endpoint_list(str(sample), BASE_URL)
        assert len(endpoints) > 0
        methods = {ep.method for ep in endpoints}
        assert HttpMethod.GET in methods
