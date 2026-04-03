"""
Identity and authentication profile models.

An IdentityProfile represents a single authenticated user or role
used during BAC testing. The tool replays requests across all
configured identities to compare authorization outcomes.
"""

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class AuthMechanism(str, Enum):
    """Supported authentication mechanisms."""

    BEARER = "bearer"
    COOKIE = "cookie"
    HEADER = "header"
    NONE = "none"


class IdentityProfile(BaseModel):
    """
    A single authenticated identity for BAC testing.

    Each identity represents a distinct user/role combination.
    The tool uses these profiles to build request headers and
    compare authorization outcomes across roles.

    Example:
        IdentityProfile(
            name="alice",
            role="user",
            auth_mechanism=AuthMechanism.BEARER,
            token="eyJ...",
            owned_object_ids=["101", "102"],
        )
    """

    name: str = Field(..., description="Human-readable label for this identity (e.g. 'alice').")
    role: str = Field(
        ...,
        description="Role this identity represents (e.g. 'user', 'admin', 'guest').",
    )
    auth_mechanism: AuthMechanism = Field(
        ...,
        description="How this identity authenticates.",
    )
    token: str | None = Field(
        default=None,
        description="Bearer token value (used when auth_mechanism is 'bearer').",
    )
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Cookie key/value pairs (used when auth_mechanism is 'cookie').",
    )
    custom_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary headers to include in every request for this identity.",
    )
    owned_object_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Object IDs this identity legitimately owns. "
            "Used to detect cross-identity IDOR by confirming another identity "
            "can access these records."
        ),
    )
    notes: str | None = Field(
        default=None,
        description="Optional notes about this identity (e.g. 'standard free-tier user').",
    )

    @field_validator("name", "role")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name and role must not be blank strings")
        return v.strip()

    model_config = {"frozen": True}
