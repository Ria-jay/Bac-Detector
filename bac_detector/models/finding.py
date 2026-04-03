"""
Finding data models.

A Finding represents a detected or potential broken access control issue,
with all information needed for a pentest report and for reproduction.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """
    Finding severity, aligned with common pentest reporting scales.

    CRITICAL: Direct, exploitable access to sensitive data or admin functions.
    HIGH:     Likely exploitable with minor effort.
    MEDIUM:   Exploitable under specific conditions.
    LOW:      Minor inconsistency, low immediate impact.
    INFO:     Informational, not an access control violation.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """
    Confidence level for a finding.

    CONFIRMED: The tool verified the issue with at least two identities
               and an ownership assertion.
    POTENTIAL: Response anomaly detected but not conclusively verified.
    FP_RISK:   Finding is flagged but has a high probability of being a
               false positive (e.g. non-deterministic response body).
    """

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    FP_RISK = "fp_risk"


class Evidence(BaseModel):
    """
    Raw evidence collected to support a finding.

    Captures the request/response data from both the attacker identity
    and (where applicable) the victim identity for direct comparison.
    """

    attacker_identity: str = Field(..., description="Identity that made the unauthorized request.")
    victim_identity: str | None = Field(
        default=None,
        description="Identity that legitimately owns the resource, if known.",
    )
    object_id: str | None = Field(
        default=None,
        description="The object identifier used in the request.",
    )
    attacker_status_code: int = Field(..., description="HTTP status code from the attacker request.")
    victim_status_code: int | None = Field(
        default=None,
        description="HTTP status code from the legitimate owner's request.",
    )
    attacker_body_snippet: str = Field(
        default="",
        description="First 256 chars of the attacker's response body.",
    )
    attacker_body_hash: str = Field(
        ...,
        description="Body hash from the attacker's response for deduplication.",
    )
    diff_summary: str = Field(
        ...,
        description="Human-readable explanation of what differs between the responses.",
    )
    requested_url: str = Field(..., description="Full URL that was requested.")

    model_config = {"frozen": True}


class Finding(BaseModel):
    """
    A single broken access control finding.

    Contains everything needed to include this finding in a pentest report:
    description, evidence, reproduction steps, impact, and remediation.
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this finding.",
    )
    title: str = Field(..., description="Short, descriptive title of the finding.")
    category: str = Field(
        ...,
        description="BAC category (e.g. 'IDOR', 'horizontal_escalation', 'vertical_escalation').",
    )
    severity: Severity = Field(..., description="Severity rating.")
    confidence: Confidence = Field(..., description="Confidence level.")
    endpoint_key: str = Field(
        ...,
        description="The endpoint this finding applies to (METHOD /path).",
    )
    endpoint_url: str = Field(..., description="Full URL of the affected endpoint.")
    http_method: str = Field(..., description="HTTP method of the affected endpoint.")
    evidence: Evidence = Field(..., description="Supporting evidence for this finding.")
    description: str = Field(..., description="Explanation of the finding.")
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Step-by-step guide to reproduce the finding.",
    )
    why_bac: str = Field(
        ...,
        description="Explanation of why this constitutes broken access control.",
    )
    business_impact: str = Field(
        ...,
        description="Potential impact on the business or application.",
    )
    remediation: str = Field(
        ...,
        description="Recommended fix or mitigation.",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"frozen": True}
