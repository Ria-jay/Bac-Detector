"""
Reporters — terminal summary, JSON findings, and Markdown pentest report.

Public API:
    write_all_reports(result, output_config)    -> ReportPaths
    write_json_report(result, path)             -> None
    write_markdown_report(result, path)         -> None
    build_markdown_report(result)               -> str
    print_scan_summary(result)                  -> None
    ReportPaths
"""

from bac_detector.reporters.json_reporter import write_json_report
from bac_detector.reporters.markdown_reporter import (
    build_markdown_report,
    write_markdown_report,
)
from bac_detector.reporters.terminal import print_scan_summary
from bac_detector.reporters.writer import ReportPaths, write_all_reports

__all__ = [
    "ReportPaths",
    "build_markdown_report",
    "print_scan_summary",
    "write_all_reports",
    "write_json_report",
    "write_markdown_report",
]
