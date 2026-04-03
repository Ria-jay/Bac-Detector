"""
URL and path normalization utilities.

Ensures endpoints from different discovery sources are deduplicated
and compared consistently.
"""

import re
from urllib.parse import urljoin, urlparse, urlunparse

# Compiled once at module level — reused across all calls
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_NUMERIC_PATTERN = re.compile(r"^\d+$")


def normalize_path(path: str) -> str:
    """
    Normalize an API path to a canonical form.

    Converts concrete path parameter values to template placeholders.
    Strips query strings and fragments before processing so that paths
    like /api/users/123?format=json are correctly handled.

    Examples:
        /api/users/123              -> /api/users/{id}
        /api/users/123?format=json  -> /api/users/{id}
        /api/orders/abc-def         -> /api/orders/{id}
        /api/users/{user_id}        -> /api/users/{user_id}  (already templated)
        /api/users/                 -> /api/users

    Args:
        path: Raw URL path string, possibly including a query string.

    Returns:
        Normalized path with numeric/UUID segments replaced by {id}
        and query strings/fragments stripped.
    """
    # Strip query string and fragment before any other processing
    path = path.split("?")[0].split("#")[0]

    # Already-templated paths (e.g. from OpenAPI) pass through unchanged
    if "{" in path:
        return path

    segments = path.strip("/").split("/")
    normalized = []
    for segment in segments:
        # Skip empty segments produced by trailing slashes (e.g. /api/users/)
        if not segment:
            continue
        if _UUID_PATTERN.fullmatch(segment):
            normalized.append("{id}")
        elif _NUMERIC_PATTERN.fullmatch(segment):
            normalized.append("{id}")
        else:
            normalized.append(segment)

    return "/" + "/".join(normalized)


def normalize_base_url(url: str) -> str:
    """
    Normalize a base URL by stripping trailing slashes and fragments.

    Args:
        url: Raw base URL string.

    Returns:
        Cleaned base URL.
    """
    parsed = urlparse(url)
    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            parsed.params,
            parsed.query,
            "",  # strip fragment
        )
    )
    return normalized


def build_url(base_url: str, path: str) -> str:
    """
    Join a base URL and a path segment safely.

    Args:
        base_url: The target base URL (e.g. https://api.example.com/v1).
        path: The endpoint path (e.g. /users/123).

    Returns:
        Full URL string.
    """
    base = normalize_base_url(base_url)
    if not base.endswith("/"):
        base += "/"
    return urljoin(base, path.lstrip("/"))


def is_object_id_param(param_name: str) -> bool:
    """
    Heuristic to identify whether a parameter name is likely an object identifier.

    These are the primary candidates for IDOR/BOLA testing.

    Args:
        param_name: The parameter name to evaluate.

    Returns:
        True if the parameter is likely an object identifier.
    """
    object_id_patterns = {
        "id",
        "user_id",
        "userid",
        "profile_id",
        "account_id",
        "order_id",
        "invoice_id",
        "tenant_id",
        "document_id",
        "customer_id",
        "admin_id",
        "item_id",
        "resource_id",
        "record_id",
        "entity_id",
        "org_id",
        "organization_id",
        "project_id",
        "file_id",
        "report_id",
        "ticket_id",
        "case_id",
        "group_id",
        "team_id",
        "member_id",
        "owner_id",
        "subject_id",
    }
    return param_name.lower() in object_id_patterns
