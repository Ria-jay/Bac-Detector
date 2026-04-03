"""
ScanResult model — the top-level artifact produced by a complete scan.

This object flows through the entire pipeline and is the input to all reporters.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from bac_detector.models.finding import Finding


class ScanStatus(str, Enum):
    """Lifecycle status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class ScanResult(BaseModel):
    """
    The complete output of a BAC Detector scan.

    Aggregates all discovered endpoints, tested identities, authorization
    matrix data, and findings into a single serializable object.

    This is the input to all reporters (JSON, Markdown, terminal).
    """

    scan_id: str = Field(..., description="Unique identifier for this scan run.")
    target: str = Field(..., description="Target base URL that was scanned.")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = Field(default=None)

    # Discovery summary
    endpoints_discovered: int = Field(default=0)
    discovery_sources_used: list[str] = Field(default_factory=list)

    # Full endpoint list — populated by the discovery phase.
    # Stored as plain dicts for serialization; cast via Endpoint.model_validate() when needed.
    endpoints: list[dict] = Field(
        default_factory=list,
        description="Serialized Endpoint objects discovered during the scan.",
    )

    # Testing summary — populated by the replay phase
    requests_made: int = Field(default=0)
    requests_errored: int = Field(default=0)
    identities_tested: list[str] = Field(
        default_factory=list,
        description="Names of IdentityProfiles used during this scan.",
    )

    # Raw responses — populated by the replay phase.
    # Stored as plain dicts; cast via ResponseMeta.model_validate() when needed.
    raw_responses: list[dict] = Field(
        default_factory=list,
        description="Serialized ResponseMeta objects from the replay phase.",
    )

    # Findings — populated by the detection phase (Phase 4)
    findings: list[Finding] = Field(default_factory=list)

    # Authorization matrix: endpoint_key -> identity_name -> status_code.
    # Compact summary form for quick display. Full detail is in raw_responses.
    auth_matrix: dict[str, dict[str, int]] = Field(
        default_factory=dict,
        description="Sparse matrix: endpoint_key -> identity_name -> HTTP status code.",
    )

    # Errors and warnings accumulated during the scan
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        """Return scan duration in seconds, or None if not yet finished."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def finding_counts_by_severity(self) -> dict[str, int]:
        """Return a count of findings grouped by severity."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def confirmed_findings(self) -> list[Finding]:
        """Return only findings with confidence=CONFIRMED."""
        from bac_detector.models.finding import Confidence

        return [f for f in self.findings if f.confidence == Confidence.CONFIRMED]

    model_config = {"frozen": False}  # mutable — pipeline stages populate fields
