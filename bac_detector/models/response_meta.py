"""
Response metadata model.

Captures the essential attributes of an HTTP response needed by the
comparators and detection engine — without storing full response bodies,
which keeps memory usage bounded during large scans.
"""

import hashlib
import json
from datetime import datetime

from pydantic import BaseModel, Field

# Bodies larger than this are not JSON-parsed — just too slow and memory-hungry
_MAX_JSON_PARSE_BYTES = 1024 * 512  # 512 KB


def _hash_body(body: str) -> str:
    """Return a short SHA-256 hex digest of a response body string."""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def _extract_json_keys(body: str) -> list[str]:
    """
    Extract top-level keys from a JSON response body.

    Returns an empty list if the body is not valid JSON, not a dict,
    or exceeds the size guard threshold.
    """
    # Guard against multi-megabyte bodies before any parsing
    if len(body) > _MAX_JSON_PARSE_BYTES:
        return []
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return sorted(parsed.keys())
    except (json.JSONDecodeError, ValueError):
        pass
    return []


class ResponseMeta(BaseModel):
    """
    Captured metadata from a single HTTP request/response pair.

    Stores enough information for comparison and evidence generation
    without retaining the full response body.
    """

    status_code: int = Field(..., description="HTTP response status code.")
    body_hash: str = Field(..., description="Short SHA-256 hash of the response body.")
    body_length: int = Field(..., description="Byte length of the response body.")
    body_snippet: str = Field(
        default="",
        description="First 256 chars of the response body, for evidence display.",
    )
    content_type: str | None = Field(
        default=None,
        description="Value of the Content-Type response header.",
    )
    json_keys: list[str] = Field(
        default_factory=list,
        description="Top-level JSON keys if the response is a JSON object.",
    )
    latency_ms: float = Field(..., description="Round-trip latency in milliseconds.")
    endpoint_key: str = Field(
        ...,
        description="Endpoint key (METHOD /path) this response belongs to.",
    )
    identity_name: str = Field(
        ...,
        description="Name of the IdentityProfile that made this request.",
    )
    object_id_used: str | None = Field(
        default=None,
        description="Object ID substituted in the request path/query, if any.",
    )
    requested_url: str = Field(..., description="The actual URL that was requested.")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = Field(
        default=None,
        description="Set if the request failed with a network or timeout error.",
    )

    @classmethod
    def from_response(
        cls,
        *,
        status_code: int,
        body: str,
        content_type: str | None,
        latency_ms: float,
        endpoint_key: str,
        identity_name: str,
        requested_url: str,
        object_id_used: str | None = None,
    ) -> "ResponseMeta":
        """
        Factory method to build a ResponseMeta from raw response data.

        Args:
            status_code: HTTP status code.
            body: Full response body as a string.
            content_type: Content-Type header value.
            latency_ms: Request round-trip time in ms.
            endpoint_key: Canonical endpoint identifier.
            identity_name: Which identity made this request.
            requested_url: The full URL that was requested.
            object_id_used: Object ID in the request, if any.

        Returns:
            Populated ResponseMeta instance.
        """
        return cls(
            status_code=status_code,
            body_hash=_hash_body(body),
            body_length=len(body.encode("utf-8", errors="replace")),
            body_snippet=body[:256],
            content_type=content_type,
            json_keys=_extract_json_keys(body),
            latency_ms=latency_ms,
            endpoint_key=endpoint_key,
            identity_name=identity_name,
            object_id_used=object_id_used,
            requested_url=requested_url,
        )

    @property
    def is_success(self) -> bool:
        """True if status code is in the 2xx range."""
        return 200 <= self.status_code < 300

    @property
    def is_client_error(self) -> bool:
        """True if status code is in the 4xx range."""
        return 400 <= self.status_code < 500

    @property
    def is_access_denied(self) -> bool:
        """True if the response is a 401 or 403."""
        return self.status_code in (401, 403)

    model_config = {"frozen": True}
