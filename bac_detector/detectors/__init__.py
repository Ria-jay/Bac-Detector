"""
Detection engine — BAC detectors and confidence scoring.

Public API:
    run_detection(matrix, baselines, profiles)  -> list[Finding]
    detect_idor(matrix, baselines, profiles)    -> list[Finding]
    detect_vertical_escalation(matrix, profiles)   -> list[Finding]
    detect_horizontal_escalation(matrix, profiles) -> list[Finding]
"""

from bac_detector.detectors.escalation import (
    detect_horizontal_escalation,
    detect_vertical_escalation,
)
from bac_detector.detectors.idor import detect_idor
from bac_detector.detectors.runner import run_detection

__all__ = [
    "detect_horizontal_escalation",
    "detect_idor",
    "detect_vertical_escalation",
    "run_detection",
]
