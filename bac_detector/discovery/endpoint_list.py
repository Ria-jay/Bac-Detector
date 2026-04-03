"""
Explicit endpoint list parser.

Reads a plain-text file where each line is one of:
  METHOD /path
  /path                  (method defaults to GET)
  # comment             (ignored)
  (blank line)          (ignored)

Path parameters may be written as:
  GET /api/users/{user_id}
  GET /api/users/:user_id     (colon-style is converted to brace-style)
  GET /api/users/[user_id]    (bracket-style is converted to brace-style)

Produces Endpoint objects with path parameters inferred from brace segments.
"""

from __future__ import annotations

import re
from pathlib import Path

from bac_detector.models.endpoint import (
    Endpoint,
    HttpMethod,
    Parameter,
    ParameterLocation,
)
from bac_detector.utils.logging import get_logger
from bac_detector.utils.normalization import is_object_id_param

log = get_logger(__name__)

# Regex to parse a line: optional METHOD, required path
# Handles:  GET /api/users/{id}
#           /api/users/{id}
#           POST   /api/orders
_LINE_RE = re.compile(
    r"^\s*(?:(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(/\S*)\s*$",
    re.IGNORECASE,
)

# Convert :param and [param] styles to {param}
_COLON_PARAM_RE = re.compile(r"/:([a-zA-Z_][a-zA-Z0-9_]*)")
_BRACKET_PARAM_RE = re.compile(r"/\[([a-zA-Z_][a-zA-Z0-9_]*)\]")

# Extract all {param} segments from a path template
_BRACE_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

# Map string -> HttpMethod
_METHOD_MAP: dict[str, HttpMethod] = {m.value: m for m in HttpMethod}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_endpoint_list(path: str | Path, base_url: str) -> list[Endpoint]:
    """
    Parse an explicit endpoint list file into Endpoint objects.

    Args:
        path: Path to the endpoint list file.
        base_url: Base URL to attach to each discovered endpoint.

    Returns:
        List of Endpoint objects.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file contains no valid endpoint lines.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Endpoint list file not found: {file_path}")

    lines = file_path.read_text(encoding="utf-8").splitlines()
    endpoints, errors = _parse_lines(lines, base_url, source_label=str(file_path))

    if errors:
        for err in errors:
            log.warning("endpoint_list_parse_warning", message=err)

    log.info(
        "endpoint_list_parsed",
        file=str(file_path),
        count=len(endpoints),
        skipped=len(errors),
    )
    return endpoints


def parse_endpoint_list_text(text: str, base_url: str) -> list[Endpoint]:
    """
    Parse endpoint list content from a string instead of a file.

    Useful for testing and for in-memory content.

    Args:
        text: Endpoint list content.
        base_url: Base URL to attach to each discovered endpoint.

    Returns:
        List of Endpoint objects.
    """
    lines = text.splitlines()
    endpoints, _ = _parse_lines(lines, base_url, source_label="<string>")
    return endpoints


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------


def _parse_lines(
    lines: list[str],
    base_url: str,
    source_label: str,
) -> tuple[list[Endpoint], list[str]]:
    """
    Parse a list of text lines into Endpoint objects.

    Returns:
        Tuple of (valid endpoints, error/warning messages).
    """
    endpoints: list[Endpoint] = []
    errors: list[str] = []
    seen_keys: set[str] = set()

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue

        endpoint, error = _parse_line(line, base_url, line_num, source_label)
        if error:
            errors.append(error)
            continue
        if endpoint is None:
            continue

        # Deduplicate within this file
        key = endpoint.endpoint_key
        if key in seen_keys:
            log.debug("endpoint_list_duplicate_skipped", key=key, line=line_num)
            continue
        seen_keys.add(key)
        endpoints.append(endpoint)

    return endpoints, errors


def _parse_line(
    line: str,
    base_url: str,
    line_num: int,
    source_label: str,
) -> tuple[Endpoint | None, str | None]:
    """
    Parse a single line into an Endpoint.

    Returns:
        Tuple of (endpoint or None, error message or None).
        Exactly one of the two will be non-None on a parse failure.
    """
    # Normalise alternative param styles before matching
    normalized_line = _normalise_param_styles(line)

    match = _LINE_RE.match(normalized_line)
    if not match:
        return None, f"{source_label}:{line_num} — unrecognised format: {line!r}"

    method_str, path = match.group(1), match.group(2)

    # Default to GET if no method specified
    if method_str is None:
        method_str = "GET"
    else:
        method_str = method_str.upper()

    http_method = _METHOD_MAP.get(method_str)
    if http_method is None:
        return None, f"{source_label}:{line_num} — unknown HTTP method: {method_str!r}"

    parameters = _infer_path_parameters(path)

    endpoint = Endpoint(
        method=http_method,
        path=path,
        base_url=base_url,
        parameters=parameters,
        source="endpoint_list",
        tags=[],
        summary=None,
    )
    return endpoint, None


def _normalise_param_styles(line: str) -> str:
    """
    Convert colon-style (:id) and bracket-style ([id]) path params to brace-style ({id}).

    Examples:
        GET /api/users/:user_id/orders/:order_id
            -> GET /api/users/{user_id}/orders/{order_id}

        GET /api/docs/[doc_id]
            -> GET /api/docs/{doc_id}
    """
    line = _COLON_PARAM_RE.sub(r"/{\1}", line)
    line = _BRACKET_PARAM_RE.sub(r"/{\1}", line)
    return line


def _infer_path_parameters(path: str) -> list[Parameter]:
    """
    Infer Parameter objects from brace-style path segments.

    For example, /api/users/{user_id}/orders/{order_id} produces
    two PATH parameters: user_id and order_id.

    Args:
        path: Normalized path template with {param} placeholders.

    Returns:
        List of Parameter objects for all path parameters found.
    """
    params: list[Parameter] = []
    for match in _BRACE_PARAM_RE.finditer(path):
        name = match.group(1)
        params.append(
            Parameter(
                name=name,
                location=ParameterLocation.PATH,
                likely_object_id=is_object_id_param(name),
                required=True,  # path params are always required
                schema_type=None,
                example_value=None,
            )
        )
    return params
