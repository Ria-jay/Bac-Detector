"""
OpenAPI / Swagger specification parser.

Supports:
  - OpenAPI 3.x (application/json or application/yaml)
  - Swagger 2.0
  - Local file paths (JSON or YAML)
  - Remote URLs (fetched with httpx sync client)

Produces a list of Endpoint objects with full parameter metadata,
including path, query, and request-body parameter hints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from bac_detector.models.endpoint import (
    Endpoint,
    HttpMethod,
    Parameter,
    ParameterLocation,
)
from bac_detector.utils.logging import get_logger
from bac_detector.utils.normalization import is_object_id_param

log = get_logger(__name__)

# HTTP methods that appear as keys inside OpenAPI path items
_OPENAPI_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

# Map from lowercase string -> HttpMethod enum
_METHOD_MAP: dict[str, HttpMethod] = {m.value.lower(): m for m in HttpMethod}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_openapi(source: str, base_url: str) -> list[Endpoint]:
    """
    Parse an OpenAPI or Swagger spec from a file path or URL.

    Args:
        source: File path or HTTP(S) URL pointing to the spec.
        base_url: Base URL to attach to each discovered endpoint.

    Returns:
        List of Endpoint objects discovered from the spec.

    Raises:
        ValueError: If the source cannot be loaded or parsed.
        FileNotFoundError: If a local file path does not exist.
    """
    raw = _load_spec(source)
    spec_version = _detect_version(raw)
    log.info("openapi_spec_loaded", source=source, version=spec_version)

    if spec_version.startswith("3."):
        endpoints = _parse_openapi3(raw, base_url)
    elif spec_version.startswith("2."):
        endpoints = _parse_swagger2(raw, base_url)
    else:
        raise ValueError(f"Unsupported OpenAPI/Swagger version: {spec_version!r}")

    log.info("openapi_endpoints_parsed", count=len(endpoints), source=source)
    return endpoints


# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------


def _load_spec(source: str) -> dict[str, Any]:
    """
    Load a spec from a file path or HTTP URL.

    Returns the parsed dict. Supports JSON and YAML.
    """
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        return _fetch_remote_spec(source)
    return _load_local_spec(source)


def _load_local_spec(path_str: str) -> dict[str, Any]:
    """Load a spec from a local file path."""
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"OpenAPI spec file not found: {path}")

    text = path.read_text(encoding="utf-8")
    return _parse_spec_text(text)


def _fetch_remote_spec(url: str) -> dict[str, Any]:
    """
    Fetch a remote spec over HTTP using the httpx synchronous client.

    Sync is deliberate here — discovery runs before the async replay engine
    starts, keeping the code simple and avoiding event-loop concerns.
    """
    import httpx

    log.debug("openapi_fetching_remote", url=url)
    try:
        response = httpx.get(
            url,
            timeout=15.0,
            follow_redirects=True,
            headers={"Accept": "application/json, application/yaml, text/yaml, */*"},
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ValueError(f"Failed to fetch OpenAPI spec from {url!r}: {exc}") from exc

    return _parse_spec_text(response.text)


def _parse_spec_text(text: str) -> dict[str, Any]:
    """
    Parse a spec string as JSON, falling back to YAML.

    YAML is a superset of JSON so the yaml parser handles both, but
    trying json.loads first is faster for the common JSON case.
    """
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    try:
        result = yaml.safe_load(text)
        if isinstance(result, dict):
            return result
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse spec as JSON or YAML: {exc}") from exc

    raise ValueError("Spec parsed but top-level value is not a JSON/YAML object")


def _detect_version(raw: dict[str, Any]) -> str:
    """
    Detect whether a spec is OpenAPI 3.x or Swagger 2.0.

    Returns a version string like "3.0.3", "3.1.0", or "2.0".
    """
    openapi_key = raw.get("openapi", "")
    if isinstance(openapi_key, str) and openapi_key.startswith("3."):
        return openapi_key

    swagger_key = raw.get("swagger", "")
    if isinstance(swagger_key, str) and swagger_key.startswith("2."):
        return swagger_key

    # Some specs omit the version key — fall back if "paths" exists
    if "paths" in raw:
        log.warning("openapi_version_not_detected", fallback="3.0")
        return "3.0"

    raise ValueError(
        "Cannot determine spec version. Expected 'openapi' or 'swagger' key."
    )


# ---------------------------------------------------------------------------
# OpenAPI 3.x parser
# ---------------------------------------------------------------------------


def _parse_openapi3(raw: dict[str, Any], base_url: str) -> list[Endpoint]:
    """Parse an OpenAPI 3.x spec into Endpoint objects."""
    endpoints: list[Endpoint] = []
    # Guard against specs that have `paths: null`
    paths: dict[str, Any] = raw.get("paths") or {}
    components: dict[str, Any] = raw.get("components") or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path-level parameters apply to all operations under this path
        path_level_params = _parse_parameters_openapi3(
            path_item.get("parameters") or [], components
        )

        for method_str, operation in path_item.items():
            if method_str.lower() not in _OPENAPI_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            http_method = _METHOD_MAP.get(method_str.lower())
            if http_method is None:
                continue

            # Operation-level params override path-level params with same name+in
            op_params = _parse_parameters_openapi3(
                operation.get("parameters") or [], components
            )
            merged_params = _merge_parameters(path_level_params, op_params)

            # Extract request body parameter hints (object-ID fields only)
            body_params = _parse_request_body_openapi3(
                operation.get("requestBody") or {}, components
            )
            all_params = merged_params + body_params

            endpoint = Endpoint(
                method=http_method,
                path=path,
                base_url=base_url,
                parameters=all_params,
                source="openapi",
                tags=operation.get("tags") or [],
                summary=operation.get("summary") or operation.get("operationId"),
            )
            endpoints.append(endpoint)

    return endpoints


def _parse_parameters_openapi3(
    params_raw: list[Any], components: dict[str, Any]
) -> list[Parameter]:
    """Parse an OpenAPI 3.x parameters array into Parameter objects."""
    result: list[Parameter] = []
    for raw_param in params_raw:
        if not isinstance(raw_param, dict):
            continue

        raw_param = _resolve_ref(raw_param, components, "parameters")

        name = raw_param.get("name", "")
        if not name:
            # Skip parameters with missing or empty names
            continue

        location_str = raw_param.get("in", "")
        required = bool(raw_param.get("required", False))

        location = _parse_location(location_str)
        if location is None:
            # Skip unsupported locations (e.g. "cookie") at MVP
            continue

        schema = raw_param.get("schema") or {}
        schema_type = schema.get("type") if isinstance(schema, dict) else None
        example = _extract_example(raw_param, schema)

        result.append(
            Parameter(
                name=name,
                location=location,
                likely_object_id=is_object_id_param(name),
                required=required,
                schema_type=schema_type,
                example_value=str(example) if example is not None else None,
            )
        )
    return result


def _parse_request_body_openapi3(
    request_body: dict[str, Any], components: dict[str, Any]
) -> list[Parameter]:
    """
    Extract object-ID property names from a requestBody schema.

    Only inspects top-level JSON properties that look like object identifiers.
    Does not recurse into nested schemas — focused on BAC-relevant fields only.
    """
    if not request_body:
        return []

    request_body = _resolve_ref(request_body, components, "requestBodies")
    content = request_body.get("content") or {}

    # Prefer application/json; fall back to the first available content type
    json_content = content.get("application/json") or {}
    schema = json_content.get("schema") or {}
    if not schema:
        for ct_schema in content.values():
            schema = ct_schema.get("schema") or {}
            if schema:
                break

    if not schema:
        return []

    schema = _resolve_ref(schema, components, "schemas")
    return _params_from_schema(schema, components)


# ---------------------------------------------------------------------------
# Swagger 2.0 parser
# ---------------------------------------------------------------------------


def _parse_swagger2(raw: dict[str, Any], base_url: str) -> list[Endpoint]:
    """Parse a Swagger 2.0 spec into Endpoint objects."""
    endpoints: list[Endpoint] = []
    paths: dict[str, Any] = raw.get("paths") or {}
    definitions: dict[str, Any] = raw.get("definitions") or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        path_level_params = _parse_parameters_swagger2(
            path_item.get("parameters") or [], definitions
        )

        for method_str, operation in path_item.items():
            if method_str.lower() not in _OPENAPI_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            http_method = _METHOD_MAP.get(method_str.lower())
            if http_method is None:
                continue

            op_params = _parse_parameters_swagger2(
                operation.get("parameters") or [], definitions
            )
            merged_params = _merge_parameters(path_level_params, op_params)

            endpoint = Endpoint(
                method=http_method,
                path=path,
                base_url=base_url,
                parameters=merged_params,
                source="openapi",
                tags=operation.get("tags") or [],
                summary=operation.get("summary") or operation.get("operationId"),
            )
            endpoints.append(endpoint)

    return endpoints


def _parse_parameters_swagger2(
    params_raw: list[Any], definitions: dict[str, Any]
) -> list[Parameter]:
    """Parse a Swagger 2.0 parameters array into Parameter objects."""
    result: list[Parameter] = []
    components = {"schemas": definitions}

    for raw_param in params_raw:
        if not isinstance(raw_param, dict):
            continue

        raw_param = _resolve_ref(raw_param, components, "parameters")

        name = raw_param.get("name", "")
        if not name:
            continue

        location_str = raw_param.get("in", "")
        required = bool(raw_param.get("required", False))

        if location_str == "body":
            # Swagger 2.0 body param — extract object-ID schema properties
            schema = _resolve_ref(raw_param.get("schema") or {}, components, "schemas")
            result.extend(_params_from_schema(schema, components))
            continue

        location = _parse_location(location_str)
        if location is None:
            continue

        schema_type = raw_param.get("type")
        example = raw_param.get("default") or raw_param.get("x-example")

        result.append(
            Parameter(
                name=name,
                location=location,
                likely_object_id=is_object_id_param(name),
                required=required,
                schema_type=schema_type,
                example_value=str(example) if example is not None else None,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _params_from_schema(
    schema: dict[str, Any], components: dict[str, Any]
) -> list[Parameter]:
    """
    Extract body Parameter hints from a JSON schema object.

    Only inspects top-level properties and only emits parameters whose names
    look like object identifiers, keeping the list focused on BAC-relevant fields.
    """
    if not isinstance(schema, dict):
        return []

    schema_type = schema.get("type")
    properties: dict[str, Any] = {}

    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties") or {}
    elif schema_type == "array":
        items = _resolve_ref(schema.get("items") or {}, components, "schemas")
        properties = items.get("properties") or {} if isinstance(items, dict) else {}

    result = []
    for prop_name, prop_schema in properties.items():
        if not is_object_id_param(prop_name):
            continue
        if not isinstance(prop_schema, dict):
            continue
        prop_type = prop_schema.get("type")
        example = prop_schema.get("example") or prop_schema.get("default")
        result.append(
            Parameter(
                name=prop_name,
                location=ParameterLocation.BODY,
                likely_object_id=True,
                required=False,
                schema_type=prop_type,
                example_value=str(example) if example is not None else None,
            )
        )
    return result


def _resolve_ref(
    obj: dict[str, Any],
    components: dict[str, Any],
    section: str,
) -> dict[str, Any]:
    """
    Resolve a JSON Reference ($ref) one level deep.

    Only handles local #/components/... and #/definitions/... refs.
    Does not recurse — nested refs are left as-is (acceptable at MVP).

    Args:
        obj: The object that may contain a "$ref" key.
        components: The components/definitions dict from the spec.
        section: The section name for context (used in logging only).

    Returns:
        The resolved object, or the original object if no $ref is present
        or the ref cannot be resolved.
    """
    ref = obj.get("$ref", "")
    if not ref:
        return obj

    parts = ref.lstrip("#/").split("/")
    try:
        if parts[0] == "components" and len(parts) == 3:
            # #/components/schemas/User  or  #/components/parameters/UserId
            resolved = (components.get(parts[1]) or {}).get(parts[2])
        elif parts[0] == "definitions" and len(parts) == 2:
            # #/definitions/User  (Swagger 2.0)
            resolved = (components.get("schemas") or {}).get(parts[1])
        else:
            log.debug("openapi_unresolved_ref", ref=ref, reason="unrecognised_pattern")
            return {}

        return resolved if isinstance(resolved, dict) else {}
    except (IndexError, KeyError, TypeError):
        log.debug("openapi_unresolved_ref", ref=ref)
        return {}


def _parse_location(location_str: str) -> ParameterLocation | None:
    """Map an OpenAPI 'in' field value to a ParameterLocation enum member."""
    mapping = {
        "path": ParameterLocation.PATH,
        "query": ParameterLocation.QUERY,
        "header": ParameterLocation.HEADER,
        "body": ParameterLocation.BODY,
        # "cookie" intentionally omitted — not in our ParameterLocation enum
    }
    return mapping.get(location_str.lower())


def _merge_parameters(
    path_level: list[Parameter], op_level: list[Parameter]
) -> list[Parameter]:
    """
    Merge path-level and operation-level parameter lists.

    Operation-level parameters override path-level parameters
    with the same (name, location) combination.
    """
    merged: dict[tuple[str, ParameterLocation], Parameter] = {}
    for param in path_level:
        merged[(param.name, param.location)] = param
    for param in op_level:
        merged[(param.name, param.location)] = param
    return list(merged.values())


def _extract_example(raw_param: dict[str, Any], schema: dict[str, Any]) -> Any:
    """
    Pull an example value from a parameter definition or its schema.

    Checks in priority order: param.example, param.default,
    schema.example, schema.default.
    """
    for key in ("example", "default"):
        val = raw_param.get(key)
        if val is not None:
            return val
    if isinstance(schema, dict):
        for key in ("example", "default"):
            val = schema.get(key)
            if val is not None:
                return val
    return None
