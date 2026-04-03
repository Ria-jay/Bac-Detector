"""
Unit tests for the reporters module.

Tests cover JSON output structure, Markdown section generation,
output path resolution, and overwrite protection.
All tests work without writing to the filesystem where possible;
file-writing tests use tmp_path fixtures.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from bac_detector.config.loader import OutputConfig
from bac_detector.models.finding import Confidence, Evidence, Finding, Severity
from bac_detector.models.scan_result import ScanResult, ScanStatus
from bac_detector.reporters.json_reporter import (
    _build_payload,
    load_scan_result,
    write_json_report,
)
from bac_detector.reporters.markdown_reporter import build_markdown_report
from bac_detector.reporters.writer import _safe_path, write_all_reports

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _evidence(
    attacker: str = "bob",
    victim: str | None = "alice",
    object_id: str | None = "1",
    attacker_status: int = 200,
    victim_status: int | None = 200,
) -> Evidence:
    return Evidence(
        attacker_identity=attacker,
        victim_identity=victim,
        object_id=object_id,
        attacker_status_code=attacker_status,
        victim_status_code=victim_status,
        attacker_body_snippet='{"id": 1, "name": "alice", "email": "alice@example.com"}',
        attacker_body_hash="abc123",
        diff_summary="Non-owner received HTTP 200. Owner received HTTP 200. Bodies identical.",
        requested_url="https://api.example.com/api/users/1",
    )


def _finding(
    title: str = "IDOR: bob accessed alice's object",
    category: str = "IDOR",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.CONFIRMED,
    endpoint_key: str = "GET /api/users/{id}",
) -> Finding:
    return Finding(
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        endpoint_key=endpoint_key,
        endpoint_url="https://api.example.com/api/users/1",
        http_method="GET",
        evidence=_evidence(),
        description="Bob accessed Alice's profile without authorization.",
        reproduction_steps=[
            "Authenticate as 'bob'.",
            "Send GET https://api.example.com/api/users/1",
            "Observe HTTP 200 response with Alice's data.",
        ],
        why_bac="No ownership check on user_id parameter.",
        business_impact="Any user can read any other user's profile.",
        remediation="Verify authenticated user owns the requested resource.",
    )


def _empty_result() -> ScanResult:
    return ScanResult(
        scan_id="test-001",
        target="https://api.example.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2024, 6, 1, 10, 0, 0),
        finished_at=datetime(2024, 6, 1, 10, 0, 42),
        endpoints_discovered=5,
        discovery_sources_used=["openapi"],
        requests_made=20,
        identities_tested=["alice", "bob"],
    )


def _result_with_findings() -> ScanResult:
    r = _empty_result()
    r.findings = [
        _finding(confidence=Confidence.CONFIRMED, severity=Severity.HIGH),
        _finding(
            title="Vertical escalation: user accessed admin",
            category="vertical_escalation",
            confidence=Confidence.POTENTIAL,
            severity=Severity.MEDIUM,
            endpoint_key="GET /api/admin/users",
        ),
        _finding(
            title="FP risk finding",
            category="IDOR",
            confidence=Confidence.FP_RISK,
            severity=Severity.INFO,
        ),
    ]
    r.auth_matrix = {
        "GET /api/users/{id}": {"alice": 200, "bob": 200},
        "GET /api/admin/users": {"alice": 403, "bob": 200},
    }
    return r


# ---------------------------------------------------------------------------
# JSON reporter — payload structure
# ---------------------------------------------------------------------------


class TestJsonReporter:
    def test_payload_has_required_top_level_keys(self):
        result = _empty_result()
        payload = _build_payload(result)
        assert {"schema_version", "tool", "summary", "scan_result"} <= set(payload.keys())

    def test_schema_version_is_string(self):
        payload = _build_payload(_empty_result())
        assert isinstance(payload["schema_version"], str)

    def test_summary_has_scan_id(self):
        payload = _build_payload(_empty_result())
        assert payload["summary"]["scan_id"] == "test-001"

    def test_summary_has_target(self):
        payload = _build_payload(_empty_result())
        assert payload["summary"]["target"] == "https://api.example.com"

    def test_summary_counts(self):
        result = _result_with_findings()
        payload = _build_payload(result)
        assert payload["summary"]["total_findings"] == 3
        assert payload["summary"]["confirmed_findings"] == 1

    def test_summary_duration_computed(self):
        result = _empty_result()
        payload = _build_payload(result)
        assert payload["summary"]["duration_seconds"] == pytest.approx(42.0, abs=0.1)

    def test_scan_result_key_present(self):
        payload = _build_payload(_empty_result())
        assert "scan_result" in payload
        sr = payload["scan_result"]
        assert sr["scan_id"] == "test-001"
        assert sr["target"] == "https://api.example.com"

    def test_scan_result_has_findings(self):
        result = _result_with_findings()
        payload = _build_payload(result)
        sr = payload["scan_result"]
        assert len(sr["findings"]) == 3

    def test_scan_result_has_auth_matrix(self):
        result = _result_with_findings()
        payload = _build_payload(result)
        assert "GET /api/users/{id}" in payload["scan_result"]["auth_matrix"]

    def test_raw_responses_excluded_from_scan_result(self):
        result = _result_with_findings()
        result.raw_responses = [{"status_code": 200, "body_hash": "abc"}]
        payload = _build_payload(result)
        assert "raw_responses" not in payload["scan_result"]

    def test_scan_result_preserves_metadata(self):
        result = _empty_result()
        payload = _build_payload(result)
        sr = payload["scan_result"]
        assert sr["endpoints_discovered"] == 5
        assert sr["requests_made"] == 20
        assert sr["identities_tested"] == ["alice", "bob"]

    def test_writes_valid_json_file(self, tmp_path: Path):
        result = _result_with_findings()
        out = tmp_path / "findings.json"
        write_json_report(result, out)
        assert out.exists()
        loaded = json.loads(out.read_text())
        # Top level has wrapper keys
        assert loaded["schema_version"] == "1.0"
        assert loaded["summary"]["scan_id"] == "test-001"
        # scan_result key has full data
        assert len(loaded["scan_result"]["findings"]) == 3

    def test_creates_parent_directory(self, tmp_path: Path):
        result = _empty_result()
        out = tmp_path / "subdir" / "nested" / "findings.json"
        write_json_report(result, out)
        assert out.exists()

    def test_load_scan_result_round_trips(self, tmp_path: Path):
        result = _result_with_findings()
        out = tmp_path / "findings.json"
        write_json_report(result, out)
        loaded = load_scan_result(out)
        assert loaded.scan_id == "test-001"
        assert loaded.target == "https://api.example.com"
        assert loaded.endpoints_discovered == 5
        assert loaded.requests_made == 20
        assert loaded.identities_tested == ["alice", "bob"]
        assert len(loaded.findings) == 3

    def test_load_scan_result_preserves_findings(self, tmp_path: Path):
        result = _result_with_findings()
        out = tmp_path / "findings.json"
        write_json_report(result, out)
        loaded = load_scan_result(out)
        f = loaded.findings[0]
        assert f.category == "IDOR"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CONFIRMED
        assert f.evidence.attacker_identity == "bob"

    def test_load_scan_result_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_scan_result(tmp_path / "missing.json")

    def test_load_scan_result_invalid_json(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json")
        with pytest.raises(ValueError):
            load_scan_result(bad)


# ---------------------------------------------------------------------------
# Markdown reporter
# ---------------------------------------------------------------------------


class TestMarkdownReporter:
    def test_contains_title(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "# Broken Access Control" in md

    def test_contains_target(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "https://api.example.com" in md

    def test_executive_summary_present(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "## Executive Summary" in md

    def test_scan_metadata_present(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "## Scan Metadata" in md
        assert "test-001" in md

    def test_no_findings_message(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "No access control issues" in md

    def test_confirmed_findings_section(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "## Confirmed Findings" in md

    def test_potential_findings_section(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "Potential Findings" in md

    def test_low_signal_findings_section(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "Low-Signal" in md

    def test_finding_title_in_report(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "IDOR: bob accessed alice's object" in md

    def test_reproduction_steps_included(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "Authenticate as 'bob'" in md
        assert "Reproduction Steps" in md

    def test_remediation_included(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "Remediation" in md
        assert "ownership" in md.lower()

    def test_auth_matrix_section(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "## Authorization Matrix" in md
        assert "alice" in md
        assert "bob" in md

    def test_appendix_endpoints(self):
        result = _result_with_findings()
        result.endpoints = [
            {"method": "GET", "path": "/api/users/{id}", "parameters": [
                {"name": "id", "location": "path", "likely_object_id": True}
            ]},
            {"method": "GET", "path": "/api/health", "parameters": []},
        ]
        md = build_markdown_report(result)
        assert "## Appendix" in md
        assert "/api/users/{id}" in md

    def test_evidence_snippet_included(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "alice@example.com" in md

    def test_why_bac_included(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "ownership check" in md

    def test_severity_labels_present(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "🔴" in md or "🟠" in md or "🟡" in md

    def test_confidence_labels_present(self):
        result = _result_with_findings()
        md = build_markdown_report(result)
        assert "✅ Confirmed" in md or "⚠️ Potential" in md

    def test_scan_id_in_markdown(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "test-001" in md

    def test_duration_in_metadata(self):
        result = _empty_result()
        md = build_markdown_report(result)
        assert "42" in md  # 42 second duration

    def test_writes_file(self, tmp_path: Path):
        from bac_detector.reporters.markdown_reporter import write_markdown_report
        result = _result_with_findings()
        out = tmp_path / "report.md"
        write_markdown_report(result, out)
        assert out.exists()
        content = out.read_text()
        assert "# Broken Access Control" in content


# ---------------------------------------------------------------------------
# Writer / path resolution
# ---------------------------------------------------------------------------


class TestWriter:
    def test_write_all_creates_both_files(self, tmp_path: Path):
        result = _result_with_findings()
        cfg = OutputConfig(
            output_dir=str(tmp_path),
            json_findings_filename="findings.json",
            markdown_report_filename="report.md",
            overwrite=True,
        )
        paths = write_all_reports(result, cfg)
        assert paths.json_path.exists()
        assert paths.markdown_path.exists()

    def test_paths_returned(self, tmp_path: Path):
        result = _empty_result()
        cfg = OutputConfig(
            output_dir=str(tmp_path),
            json_findings_filename="f.json",
            markdown_report_filename="r.md",
            overwrite=True,
        )
        paths = write_all_reports(result, cfg)
        assert paths.json_path.name == "f.json"
        assert paths.markdown_path.name == "r.md"

    def test_safe_path_returns_original_when_not_exists(self, tmp_path: Path):
        p = tmp_path / "findings.json"
        result = _safe_path(p, overwrite=False)
        assert result == p

    def test_safe_path_overwrite_true_returns_original(self, tmp_path: Path):
        p = tmp_path / "findings.json"
        p.write_text("existing")
        result = _safe_path(p, overwrite=True)
        assert result == p

    def test_safe_path_renames_when_exists_and_no_overwrite(self, tmp_path: Path):
        p = tmp_path / "findings.json"
        p.write_text("existing")
        result = _safe_path(p, overwrite=False)
        assert result != p
        assert result.name == "findings.1.json"

    def test_safe_path_increments_counter(self, tmp_path: Path):
        p = tmp_path / "findings.json"
        p.write_text("existing")
        (tmp_path / "findings.1.json").write_text("also existing")
        result = _safe_path(p, overwrite=False)
        assert result.name == "findings.2.json"

    def test_output_dir_created_if_missing(self, tmp_path: Path):
        result = _empty_result()
        new_dir = tmp_path / "new" / "nested"
        cfg = OutputConfig(
            output_dir=str(new_dir),
            overwrite=True,
        )
        paths = write_all_reports(result, cfg)
        assert new_dir.exists()
        assert paths.json_path.exists()
