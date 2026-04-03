"""
Endpoint and parameter data models.

An Endpoint represents a single discovered API route with its method,
path template, parameters, and discovery source metadata.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class HttpMethod(str, Enum):
    """Supported HTTP methods for endpoint testing."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterLocation(str, Enum):
    """Where in a request a parameter appears."""

    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"


# Discovery source type alias for clarity
DiscoverySource = Literal["openapi", "endpoint_list", "js", "crawl"]


class Parameter(BaseModel):
    """
    A single parameter associated with an endpoint.

    The `likely_object_id` flag marks parameters that are candidates
    for IDOR/BOLA testing (e.g. user_id, order_id).
    """

    name: str = Field(..., description="Parameter name as it appears in the request.")
    location: ParameterLocation = Field(..., description="Where the parameter appears.")
    likely_object_id: bool = Field(
        default=False,
        description="Heuristic flag: True if this parameter looks like an object identifier.",
    )
    example_value: str | None = Field(
        default=None,
        description="An example or default value for this parameter.",
    )
    required: bool = Field(default=False, description="Whether the parameter is required.")
    schema_type: str | None = Field(
        default=None,
        description="JSON schema type hint (string, integer, etc.).",
    )

    model_config = {"frozen": True}


class Endpoint(BaseModel):
    """
    A discovered API endpoint.

    Represents a normalized route with its HTTP method, path template,
    parameters, and the source that surfaced it during discovery.
    """

    method: HttpMethod = Field(..., description="HTTP method for this endpoint.")
    path: str = Field(
        ...,
        description="Normalized path template, e.g. /api/users/{user_id}.",
    )
    base_url: str = Field(
        ...,
        description="Base URL of the target, e.g. https://api.example.com.",
    )
    parameters: list[Parameter] = Field(
        default_factory=list,
        description="All known parameters for this endpoint.",
    )
    source: DiscoverySource = Field(
        ...,
        description="Discovery source that surfaced this endpoint.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags from OpenAPI or other metadata.",
    )
    summary: str | None = Field(
        default=None,
        description="Short description from OpenAPI spec, if available.",
    )

    @field_validator("path")
    @classmethod
    def path_must_start_with_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            return f"/{v}"
        return v

    @property
    def full_url(self) -> str:
        """Return the full URL by joining base_url and path."""
        base = self.base_url.rstrip("/")
        return f"{base}{self.path}"

    @property
    def object_id_params(self) -> list[Parameter]:
        """Return only parameters flagged as likely object identifiers."""
        return [p for p in self.parameters if p.likely_object_id]

    @property
    def endpoint_key(self) -> str:
        """Unique key for deduplication: METHOD /path."""
        return f"{self.method.value} {self.path}"

    model_config = {"frozen": True}

