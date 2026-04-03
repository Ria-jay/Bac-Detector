"""
Comparators — pure response comparison utilities.

Public API:
    compare_responses(candidate, reference)  -> ResponseDiff
    responses_look_equivalent(a, b)          -> bool
    is_likely_nondeterministic(responses)    -> bool
    ResponseDiff
"""

from bac_detector.comparators.response import (
    ResponseDiff,
    compare_responses,
    is_likely_nondeterministic,
    responses_look_equivalent,
)

__all__ = [
    "ResponseDiff",
    "compare_responses",
    "is_likely_nondeterministic",
    "responses_look_equivalent",
]
