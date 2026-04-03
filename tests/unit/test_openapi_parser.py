"""
Unit tests for the OpenAPI / Swagger spec parser.

Tests cover OpenAPI 3.x and Swagger 2.0 parsing, parameter extraction,
$ref resolution, request body parsing, and error handling.

All tests use in-memory dicts passed via the internal parse functions
to avoid network calls. The public parse_openapi() function is tested
via the local-file path using tmp_path fixtures.
"""

import json
from pathlib import Path

import pytest
import yaml

from bac_detector.discovery.openapi_parser import (
    _detect_version,
    _merge_parameters,
    _parse_openapi3,
    _parse_request_body_openapi3,
    _parse_swagger2,
    _resolve_ref,
    parse_openapi,
)
from bac_detector.models.endpoint import HttpMethod, ParameterLocation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _minimal_openapi3(paths: dict) -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": paths,
    }


def _minimal_swagger2(paths: dict) -> dict:
    return {
        "swagger": "2.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "host": "api.example.com",
        "basePath": "/v1",
        "paths": paths,
    }


BASE_URL = "https://api.example.com"


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------


class TestDetectVersion:
    def test_openapi3(self):
        assert _detect_version({"openapi": "3.0.3"}) == "3.0.3"

    def test_openapi31(self):
        assert _detect_version({"openapi": "3.1.0"}) == "3.1.0"

    def test_swagger20(self):
        assert _detect_version({"swagger": "2.0"}) == "2.0"

    def test_fallback_with_paths(self):
        result = _detect_version({"paths": {}})
        assert result == "3.0"

    def test_no_version_no_paths_raises(self):
        with pytest.raises(ValueError, match="Cannot determine spec version"):
            _detect_version({"info": {"title": "No version"}})


# ---------------------------------------------------------------------------
# OpenAPI 3.x — basic path parsing
# ---------------------------------------------------------------------------


class TestParseOpenAPI3Basic:
    def test_single_get_endpoint(self):
        spec = _minimal_openapi3({
            "/api/users": {
                "get": {"summary": "List users", "tags": ["users"]},
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep.method == HttpMethod.GET
        assert ep.path == "/api/users"
        assert ep.base_url == BASE_URL
        assert ep.source == "openapi"
        assert ep.summary == "List users"
        assert "users" in ep.tags

    def test_multiple_methods_on_same_path(self):
        spec = _minimal_openapi3({
            "/api/items": {
                "get": {"summary": "List"},
                "post": {"summary": "Create"},
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints) == 2
        methods = {ep.method for ep in endpoints}
        assert HttpMethod.GET in methods
        assert HttpMethod.POST in methods

    def test_all_http_methods_parsed(self):
        spec = _minimal_openapi3({
            "/api/resource/{id}": {
                "get": {},
                "put": {},
                "patch": {},
                "delete": {},
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints) == 4

    def test_empty_paths_returns_empty(self):
        spec = _minimal_openapi3({})
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert endpoints == []

    def test_operationid_used_as_summary_fallback(self):
        spec = _minimal_openapi3({
            "/api/users": {
                "get": {"operationId": "listUsers"},
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert endpoints[0].summary == "listUsers"


# ---------------------------------------------------------------------------
# OpenAPI 3.x — parameter parsing
# ---------------------------------------------------------------------------


class TestParseOpenAPI3Parameters:
    def test_path_parameter_extracted(self):
        spec = _minimal_openapi3({
            "/api/users/{user_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ]
                }
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints) == 1
        params = endpoints[0].parameters
        assert len(params) == 1
        p = params[0]
        assert p.name == "user_id"
        assert p.location == ParameterLocation.PATH
        assert p.likely_object_id is True
        assert p.required is True
        assert p.schema_type == "integer"

    def test_query_parameter_extracted(self):
        spec = _minimal_openapi3({
            "/api/users": {
                "get": {
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}},
                        {"name": "user_id", "in": "query", "schema": {"type": "string"}},
                    ]
                }
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        params = endpoints[0].parameters
        assert len(params) == 2
        id_params = [p for p in params if p.likely_object_id]
        assert len(id_params) == 1
        assert id_params[0].name == "user_id"

    def test_path_level_params_inherited(self):
        spec = _minimal_openapi3({
            "/api/users/{user_id}": {
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "get": {"summary": "Get user"},
                "delete": {"summary": "Delete user"},
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints) == 2
        for ep in endpoints:
            assert any(p.name == "user_id" for p in ep.parameters)

    def test_operation_params_override_path_params(self):
        spec = _minimal_openapi3({
            "/api/users/{user_id}": {
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ],
                "get": {
                    "parameters": [
                        # Same param name+location but different schema type
                        {"name": "user_id", "in": "path", "required": True,
                         "schema": {"type": "integer"}}
                    ]
                },
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        # Only one param after merge
        params = endpoints[0].parameters
        assert len(params) == 1
        assert params[0].schema_type == "integer"  # operation-level wins

    def test_header_param_captured(self):
        spec = _minimal_openapi3({
            "/api/resource": {
                "get": {
                    "parameters": [
                        {"name": "X-Tenant-ID", "in": "header", "schema": {"type": "string"}}
                    ]
                }
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        params = endpoints[0].parameters
        assert any(p.location == ParameterLocation.HEADER for p in params)

    def test_example_value_extracted(self):
        spec = _minimal_openapi3({
            "/api/orders/{order_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "order_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "example": 42},
                        }
                    ]
                }
            }
        })
        endpoints = _parse_openapi3(spec, BASE_URL)
        p = endpoints[0].parameters[0]
        assert p.example_value == "42"


# ---------------------------------------------------------------------------
# OpenAPI 3.x — $ref resolution
# ---------------------------------------------------------------------------


class TestRefResolution:
    def test_parameter_ref_resolved(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "components": {
                "parameters": {
                    "UserId": {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                }
            },
            "paths": {
                "/api/users/{user_id}": {
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/UserId"}
                        ]
                    }
                }
            },
        }
        endpoints = _parse_openapi3(spec, BASE_URL)
        assert len(endpoints[0].parameters) == 1
        assert endpoints[0].parameters[0].name == "user_id"

    def test_unknown_ref_returns_empty(self):
        components = {"schemas": {}}
        result = _resolve_ref({"$ref": "#/components/schemas/DoesNotExist"}, components, "schemas")
        # Should return empty dict without raising
        assert result == {}

    def test_no_ref_passthrough(self):
        obj = {"name": "test", "in": "path"}
        result = _resolve_ref(obj, {}, "parameters")
        assert result is obj


# ---------------------------------------------------------------------------
# OpenAPI 3.x — request body
# ---------------------------------------------------------------------------


class TestRequestBodyParsing:
    def test_json_body_object_id_params_extracted(self):
        request_body = {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "integer"},
                            "name": {"type": "string"},
                            "order_id": {"type": "integer"},
                        },
                    }
                }
            }
        }
        params = _parse_request_body_openapi3(request_body, {})
        param_names = {p.name for p in params}
        # Only object-ID params should be extracted
        assert "user_id" in param_names
        assert "order_id" in param_names
        assert "name" not in param_names
        for p in params:
            assert p.location == ParameterLocation.BODY
            assert p.likely_object_id is True

    def test_empty_body_returns_empty(self):
        assert _parse_request_body_openapi3({}, {}) == []

    def test_non_object_schema_returns_empty(self):
        request_body = {
            "content": {
                "application/json": {
                    "schema": {"type": "string"}
                }
            }
        }
        assert _parse_request_body_openapi3(request_body, {}) == []


# ---------------------------------------------------------------------------
# Swagger 2.0 parser
# ---------------------------------------------------------------------------


class TestParseSwagger2:
    def test_basic_get_endpoint(self):
        spec = _minimal_swagger2({
            "/api/users": {
                "get": {"summary": "List users", "tags": ["users"]}
            }
        })
        endpoints = _parse_swagger2(spec, BASE_URL)
        assert len(endpoints) == 1
        assert endpoints[0].method == HttpMethod.GET
        assert endpoints[0].source == "openapi"

    def test_path_parameter(self):
        spec = _minimal_swagger2({
            "/api/users/{user_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "type": "integer",
                        }
                    ]
                }
            }
        })
        endpoints = _parse_swagger2(spec, BASE_URL)
        params = endpoints[0].parameters
        assert len(params) == 1
        assert params[0].name == "user_id"
        assert params[0].likely_object_id is True

    def test_body_param_schema_properties_extracted(self):
        spec = _minimal_swagger2({
            "/api/orders": {
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "order_id": {"type": "integer"},
                                    "description": {"type": "string"},
                                },
                            },
                        }
                    ]
                }
            }
        })
        endpoints = _parse_swagger2(spec, BASE_URL)
        params = endpoints[0].parameters
        param_names = {p.name for p in params}
        assert "order_id" in param_names
        assert "description" not in param_names


# ---------------------------------------------------------------------------
# parse_openapi() public function — local file tests
# ---------------------------------------------------------------------------


class TestParseOpenapiPublic:
    def test_load_json_file(self, tmp_path: Path):
        spec = _minimal_openapi3({
            "/api/test": {"get": {"summary": "Test endpoint"}}
        })
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(spec))
        endpoints = parse_openapi(str(spec_file), BASE_URL)
        assert len(endpoints) == 1
        assert endpoints[0].path == "/api/test"

    def test_load_yaml_file(self, tmp_path: Path):
        spec = _minimal_openapi3({
            "/api/items": {"get": {}},
            "/api/items/{item_id}": {
                "get": {
                    "parameters": [
                        {"name": "item_id", "in": "path", "required": True,
                         "schema": {"type": "string"}}
                    ]
                }
            },
        })
        spec_file = tmp_path / "openapi.yaml"
        spec_file.write_text(yaml.dump(spec))
        endpoints = parse_openapi(str(spec_file), BASE_URL)
        assert len(endpoints) == 2

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_openapi(str(tmp_path / "missing.json"), BASE_URL)

    def test_swagger2_yaml_file(self, tmp_path: Path):
        spec = _minimal_swagger2({
            "/api/v2/users": {"get": {"summary": "List users"}}
        })
        spec_file = tmp_path / "swagger.yaml"
        spec_file.write_text(yaml.dump(spec))
        endpoints = parse_openapi(str(spec_file), BASE_URL)
        assert len(endpoints) == 1

    def test_invalid_yaml_raises(self, tmp_path: Path):
        spec_file = tmp_path / "bad.yaml"
        spec_file.write_text("--- : : : invalid")
        with pytest.raises((ValueError, Exception)):
            parse_openapi(str(spec_file), BASE_URL)


# ---------------------------------------------------------------------------
# Merge parameters helper
# ---------------------------------------------------------------------------


class TestMergeParameters:
    def test_operation_overrides_path_level(self):
        from bac_detector.models.endpoint import Parameter, ParameterLocation

        path_param = Parameter(name="id", location=ParameterLocation.PATH,
                               likely_object_id=True, schema_type="string")
        op_param = Parameter(name="id", location=ParameterLocation.PATH,
                             likely_object_id=True, schema_type="integer")
        result = _merge_parameters([path_param], [op_param])
        assert len(result) == 1
        assert result[0].schema_type == "integer"

    def test_unique_params_combined(self):
        from bac_detector.models.endpoint import Parameter, ParameterLocation

        p1 = Parameter(name="user_id", location=ParameterLocation.PATH, likely_object_id=True)
        p2 = Parameter(name="order_id", location=ParameterLocation.QUERY, likely_object_id=True)
        result = _merge_parameters([p1], [p2])
        assert len(result) == 2
