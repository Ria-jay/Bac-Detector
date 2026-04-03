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
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from bac_detector.models.endpoint import (
    DiscoverySource,
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

# Map from string -> HttpMethod, lowercased
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
    return _parse_spec_text(text, hint=path.suffix)


def _fetch_remote_spec(url: str) -> dict[str, Any]:
    """
    Fetch a remote spec over HTTP using httpx synchronous client.

    We use the sync client here because discovery runs before the async
    replay engine is started — keeping it simple and predictable.
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

    content_type = response.headers.get("content-type", "")
    hint = ".yaml" if "yaml" in content_type else ".json"
    return _parse_spec_text(response.text, hint=hint)


def _parse_spec_text(text: str, hint: str = ".json") -> dict[str, Any]:
    """
    Parse a spec string as JSON or YAML.

    Tries JSON first; falls back to YAML (which also handles JSON).
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

    raise ValueError("Spec parsed but is not a JSON/YAML object (dict)")


def _detect_version(raw: dict[str, Any]) -> str:
    """
    Detect whether a spec is OpenAPI 3.x or Swagger 2.0.

    Returns a version string like "3.0", "3.1", or "2.0".
    """
    # OpenAPI 3.x uses the "openapi" key
    openapi_key = raw.get("openapi", "")
    if isinstance(openapi_key, str) and openapi_key.startswith("3."):
        return openapi_key

    # Swagger 2.0 uses the "swagger" key
    swagger_key = raw.get("swagger", "")
    if isinstance(swagger_key, str) and swagger_key.startswith("2."):
        return swagger_key

    # Some specs omit the version — treat as OpenAPI 3.0 if "paths" exists
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
    paths: dict[str, Any] = raw.get("paths", {})
    components = raw.get("components", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path-level parameters apply to all operations in this path
        path_level_params = _parse_parameters_openapi3(
            path_item.get("parameters", []), components
        )

        for method_str, operation in path_item.items():
            if method_str.lower() not in _OPENAPI_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            http_method = _METHOD_MAP.get(method_str.lower())
            if http_method is None:
                continue

            # Merge path-level and operation-level parameters
            # Operation-level params override path-level with same name+in
            op_params = _parse_parameters_openapi3(
                operation.get("parameters", []), components
            )
            merged_params = _merge_parameters(path_level_params, op_params)

            # Extract request body parameter hints
            body_params = _parse_request_body_openapi3(
                operation.get("requestBody", {}), components
            )
            all_params = merged_params + body_params

            endpoint = Endpoint(
                method=http_method,
                path=path,
                base_url=base_url,
                parameters=all_params,
                source="openapi",
                tags=operation.get("tags", []),
                summary=operation.get("summary") or operation.get("operationId"),
            )
            endpoints.append(endpoint)

    return endpoints


def _parse_parameters_openapi3(
    params_raw: list[Any], components: dict[str, Any]
) -> list[Parameter]:
    """Parse an OpenAPI 3.x parameters array."""
    result: list[Parameter] = []
    for raw_param in params_raw:
        if not isinstance(raw_param, dict):
            continue

        # Resolve $ref if present
        raw_param = _resolve_ref(raw_param, components, "parameters")

        name = raw_param.get("name", "")
        location_str = raw_param.get("in", "")
        required = bool(raw_param.get("required", False))

        location = _parse_location(location_str)
        if location is None:
            continue  # skip unsupported locations like "cookie" at MVP

        schema = raw_param.get("schema", {})
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
    Extract top-level JSON body property names from a requestBody.

    We don't recurse into nested schemas — only grab top-level properties
    that look like object identifiers (e.g. user_id, order_id).
    """
    if not request_body:
        return []

    request_body = _resolve_ref(request_body, components, "requestBodies")
    content = request_body.get("content", {})

    # Prefer application/json
    json_content = content.get("application/json", {})
    schema = json_content.get("schema", {})
    if not schema:
        # Try the first available content type
        for ct_schema in content.values():
            schema = ct_schema.get("schema", {})
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
    paths: dict[str, Any] = raw.get("paths", {})
    definitions = raw.get("definitions", {})

    # Swagger 2.0 uses a flat "definitions" key, not "components/schemas"
    # We wrap it in a components-shaped dict for reuse of helper functions
    components = {"schemas": definitions}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        path_level_params = _parse_parameters_swagger2(
            path_item.get("parameters", []), definitions
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
                operation.get("parameters", []), definitions
            )
            merged_params = _merge_parameters(path_level_params, op_params)

            endpoint = Endpoint(
                method=http_method,
                path=path,
                base_url=base_url,
                parameters=merged_params,
                source="openapi",
                tags=operation.get("tags", []),
                summary=operation.get("summary") or operation.get("operationId"),
            )
            endpoints.append(endpoint)

    return endpoints


def _parse_parameters_swagger2(
    params_raw: list[Any], definitions: dict[str, Any]
) -> list[Parameter]:
    """Parse a Swagger 2.0 parameters array."""
    result: list[Parameter] = []
    components = {"schemas": definitions}

    for raw_param in params_raw:
        if not isinstance(raw_param, dict):
            continue

        raw_param = _resolve_ref(raw_param, components, "parameters")

        name = raw_param.get("name", "")
        location_str = raw_param.get("in", "")
        required = bool(raw_param.get("required", False))

        if location_str == "body":
            # Swagger 2.0 body params — extract schema properties
            schema = raw_param.get("schema", {})
            schema = _resolve_ref(schema, components, "schemas")
            body_params = _params_from_schema(schema, components)
            result.extend(body_params)
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

    Only inspects top-level properties. Skips arrays and primitives.
    Only emits parameters whose names look like object identifiers to
    keep the list focused on BAC-relevant fields.
    """
    if not isinstance(schema, dict):
        return []

    schema_type = schema.get("type")
    properties: dict[str, Any] = {}

    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties", {})
    elif schema_type == "array":
        items = schema.get("items", {})
        items = _resolve_ref(items, components, "schemas")
        properties = items.get("properties", {}) if isinstance(items, dict) else {}

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
    Resolve a $ref pointer one level deep.

    Only handles local #/components/... and #/definitions/... refs.
    Does not recurse into nested refs — that level of complexity is
    not required for MVP BAC detection.

    Args:
        obj: The object that may contain a "$ref" key.
        components: The components/definitions dict from the spec.
        section: Which section to look in (e.g. "schemas", "parameters").

    Returns:
        The resolved object, or the original object if no $ref present.
    """
    ref = obj.get("$ref", "")
    if not ref:
        return obj

    # Patterns:
    #   #/components/schemas/User
    #   #/components/parameters/UserId
    #   #/definitions/User  (Swagger 2.0)
    parts = ref.lstrip("#/").split("/")
    try:
        if parts[0] == "components":
            # parts = ["components", "schemas", "User"]
            resolved = components.get(parts[1], {}).get(parts[2], {})
        elif parts[0] == "definitions":
            # parts = ["definitions", "User"]
            resolved = components.get("schemas", {}).get(parts[1], {})
        else:
            return obj
        return resolved if isinstance(resolved, dict) else obj
    except (IndexError, KeyError):
        log.debug("openapi_unresolved_ref", ref=ref)
        return obj


def _parse_location(location_str: str) -> ParameterLocation | None:
    """Map an OpenAPI 'in' string to a ParameterLocation enum value."""
    mapping = {
        "path": ParameterLocation.PATH,
        "query": ParameterLocation.QUERY,
        "header": ParameterLocation.HEADER,
        "body": ParameterLocation.BODY,
        # "cookie" is not in our ParameterLocation enum — skip it
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


def _extract_example(
    raw_param: dict[str, Any], schema: dict[str, Any]
) -> Any:
    """
    Try to pull an example value from a parameter or its schema.

    Checks in priority order: example, default, schema.example, schema.default.
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
