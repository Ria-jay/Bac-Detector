"""
Analyzers — authorization matrix and baseline builder.

Public API:
    build_matrix(responses)            -> AuthMatrix
    build_baselines(matrix, profiles)  -> list[Baseline]
    AuthMatrix
    Baseline
"""

from bac_detector.analyzers.baseline import Baseline, build_baselines
from bac_detector.analyzers.matrix import AuthMatrix, build_matrix

__all__ = [
    "AuthMatrix",
    "Baseline",
    "build_baselines",
    "build_matrix",
]
