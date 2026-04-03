"""
Configuration loader for BAC Detector.

Reads a YAML config file and validates it against the ScanConfig schema.
All scan behaviour is driven by this config — no magic defaults hidden in code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from bac_detector.models.identity import AuthMechanism, IdentityProfile


# ---------------------------------------------------------------------------
# Sub-config models
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    """Configuration for the scan target."""

    base_url: str = Field(..., description="Base URL of the application under test.")
    api_base_url: str | None = Field(
        default=None,
        description="API-specific base URL if different from base_url.",
    )
    openapi_url: str | None = Field(
        default=None,
        description="URL or file path to an OpenAPI/Swagger spec.",
    )
    endpoint_list_path: str | None = Field(
        default=None,
        description="Path to a plain-text file of endpoints to test.",
    )
    scope_allowlist: list[str] = Field(
        default_factory=list,
        description=(
            "URL prefixes that are in scope. Requests outside these prefixes are blocked. "
            "If empty, all paths under base_url are in scope."
        ),
    )

    @field_validator("base_url", "api_base_url")
    @classmethod
    def must_be_http(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith(("http://", "https://")):
            raise ValueError(f"URL must start with http:// or https://, got: {v!r}")
        return v


class CrawlConfig(BaseModel):
    """HTML crawl settings (Phase 7 feature — accepted in config for forward compatibility)."""

    enabled: bool = Field(default=False, description="Enable HTML crawling.")
    max_depth: int = Field(default=3, ge=1, le=10)
    max_requests: int = Field(default=100, ge=1, le=1000)
    respect_robots_txt: bool = Field(default=True)


class ThrottleConfig(BaseModel):
    """Rate limiting and request budget configuration."""

    requests_per_second: float = Field(
        default=2.0,
        ge=0.1,
        le=50.0,
        description="Maximum requests per second across all identities.",
    )
    request_budget: int = Field(
        default=500,
        ge=1,
        description="Hard cap on total requests per scan. Scan stops when reached.",
    )
    timeout_seconds: float = Field(
        default=15.0,
        ge=1.0,
        le=120.0,
        description="Per-request HTTP timeout in seconds.",
    )
    retry_on_error: bool = Field(
        default=False,
        description="Whether to retry failed requests once before giving up.",
    )


class SafetyConfig(BaseModel):
    """Safety and operation mode configuration."""

    dry_run: bool = Field(
        default=False,
        description="If True, print requests but do not send them.",
    )
    read_only: bool = Field(
        default=True,
        description="If True, skip all non-GET requests.",
    )
    lab_mode: bool = Field(
        default=False,
        description=(
            "Enable write-operation testing (POST/PUT/PATCH/DELETE). "
            "Only use in isolated lab environments."
        ),
    )
    verify_ssl: bool = Field(
        default=True,
        description="Whether to verify TLS certificates.",
    )
    enabled_methods: list[Literal["GET", "POST", "PUT", "PATCH", "DELETE"]] = Field(
        default_factory=lambda: ["GET"],
        description="HTTP methods to include in testing.",
    )

    @model_validator(mode="after")
    def lab_mode_requires_explicit_methods(self) -> "SafetyConfig":
        write_methods = {"POST", "PUT", "PATCH", "DELETE"}
        has_write_methods = bool(write_methods.intersection(self.enabled_methods))
        if has_write_methods and not self.lab_mode:
            raise ValueError(
                "Write HTTP methods (POST/PUT/PATCH/DELETE) require lab_mode: true. "
                "Only enable this in isolated lab environments."
            )
        return self


class IdentityConfig(BaseModel):
    """A single identity profile as it appears in the YAML config file."""

    name: str
    role: str
    auth_mechanism: AuthMechanism
    token: str | None = None
    cookies: dict[str, str] = Field(default_factory=dict)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    owned_object_ids: list[str] = Field(default_factory=list)
    notes: str | None = None

    @model_validator(mode="after")
    def bearer_requires_token(self) -> "IdentityConfig":
        """Catch the common misconfiguration of bearer auth without a token."""
        if self.auth_mechanism == AuthMechanism.BEARER and not self.token:
            raise ValueError(
                f"Identity {self.name!r}: auth_mechanism is 'bearer' but no token is set. "
                "Provide a token or change auth_mechanism to 'none'."
            )
        if self.auth_mechanism == AuthMechanism.COOKIE and not self.cookies:
            raise ValueError(
                f"Identity {self.name!r}: auth_mechanism is 'cookie' but no cookies are set. "
                "Provide at least one cookie or change auth_mechanism to 'none'."
            )
        return self

    def to_identity_profile(self) -> IdentityProfile:
        """Convert config representation to the IdentityProfile model."""
        return IdentityProfile(
            name=self.name,
            role=self.role,
            auth_mechanism=self.auth_mechanism,
            token=self.token,
            cookies=self.cookies,
            custom_headers=self.custom_headers,
            owned_object_ids=self.owned_object_ids,
            notes=self.notes,
        )


class OutputConfig(BaseModel):
    """Output file paths for scan reports."""

    output_dir: str = Field(
        default="./results",
        description="Directory where output files are written.",
    )
    json_findings_filename: str = Field(default="findings.json")
    markdown_report_filename: str = Field(default="report.md")
    overwrite: bool = Field(
        default=False,
        description="If True, overwrite existing output files.",
    )


class LogConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    json_logs: bool = Field(
        default=False,
        description="If True, emit JSON-formatted log lines (useful for log aggregation).",
    )


class GraphAnalysisConfig(BaseModel):
    """
    Configuration for the optional graph-based authorization analysis layer (G3).

    Graph analysis runs after the standard Phase 4 detection and adds
    cross-endpoint reasoning to surface inconsistencies that isolated
    request-pair comparisons cannot detect.

    Set enabled: true to activate. All other flags default to on when
    graph analysis is enabled, so the minimal config is just:

        graph_analysis:
          enabled: true
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable graph-based authorization analysis after Phase 4 detection. "
            "Default: false — graph analysis is opt-in."
        ),
    )
    infer_ownership: bool = Field(
        default=True,
        description=(
            "Use response body fields (owner_id, user_id, etc.) to infer resource "
            "ownership and detect ownership inconsistencies."
        ),
    )
    infer_tenant_boundaries: bool = Field(
        default=True,
        description=(
            "Detect tenant boundary inconsistencies by comparing tenant_id / "
            "organization_id fields across identity responses for the same resource."
        ),
    )
    enable_hidden_privilege_path_checks: bool = Field(
        default=True,
        description=(
            "Check for admin sub-endpoints that are accessible even when the main "
            "admin endpoint is denied (hidden privilege escalation paths)."
        ),
    )
    min_confidence: Literal["high", "medium", "low"] = Field(
        default="low",
        description=(
            "Minimum confidence level for graph findings to be included in output. "
            "'high' = confirmed only, 'medium' = confirmed + potential, "
            "'low' = all findings including FP_RISK."
        ),
    )


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------


class ScanConfig(BaseModel):
    """
    Top-level configuration for a BAC Detector scan.

    Loaded from a YAML config file and validated before any scan work begins.
    """

    target: TargetConfig
    identities: list[IdentityConfig] = Field(
        ...,
        min_length=2,
        description="At least two identity profiles are required to compare authorization.",
    )
    throttle: ThrottleConfig = Field(default_factory=ThrottleConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    log_config: LogConfig = Field(
        default_factory=LogConfig,
        description="Logging level and format settings.",
    )
    graph_analysis: GraphAnalysisConfig = Field(
        default_factory=GraphAnalysisConfig,
        description="Optional graph-based authorization analysis settings.",
    )

    @model_validator(mode="after")
    def at_least_one_discovery_source(self) -> "ScanConfig":
        has_openapi = self.target.openapi_url is not None
        has_endpoint_list = self.target.endpoint_list_path is not None
        has_crawl = self.crawl.enabled
        if not (has_openapi or has_endpoint_list or has_crawl):
            raise ValueError(
                "At least one discovery source is required: "
                "target.openapi_url, target.endpoint_list_path, or crawl.enabled=true."
            )
        return self

    @property
    def identity_profiles(self) -> list[IdentityProfile]:
        """Return all identities as IdentityProfile model instances."""
        return [ic.to_identity_profile() for ic in self.identities]

    @property
    def effective_api_base_url(self) -> str:
        """Return the API base URL, falling back to base_url if not set."""
        return self.target.api_base_url or self.target.base_url


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: str | Path) -> ScanConfig:
    """
    Load and validate a YAML config file into a ScanConfig instance.

    The YAML key for logging settings is ``log_config`` (not ``logging``,
    which would shadow the Python stdlib module name).

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Validated ScanConfig.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config file is invalid YAML or fails validation.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must be a YAML mapping, got: {type(raw).__name__}")

    return ScanConfig.model_validate(raw)
