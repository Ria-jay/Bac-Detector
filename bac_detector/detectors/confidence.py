"""
Confidence scoring for BAC findings.

Assigns a Confidence level (CONFIRMED / POTENTIAL / FP_RISK) to a
candidate finding based on the available evidence. Keeps the scoring
rules explicit and in one place so they are easy to audit and adjust.
"""

from __future__ import annotations

from bac_detector.comparators.response import ResponseDiff
from bac_detector.models.finding import Confidence
from bac_detector.models.response_meta import ResponseMeta


def score_idor_confidence(
    *,
    attacker_meta: ResponseMeta,
    owner_meta: ResponseMeta | None,
    diff: ResponseDiff,
) -> Confidence:
    """
    Score confidence for an IDOR / BOLA candidate finding.

    Called only when ownership has already been established — the caller
    has confirmed the attacker does not own the object in question.

    CONFIRMED requires:
      - The attacker got a 2xx response
      - The owner also got a 2xx response
      - The responses are structurally similar (same body hash OR same JSON keys)
        indicating the attacker received the real resource, not a generic error page

    POTENTIAL: attacker got 2xx but we can't verify data similarity
    (no owner baseline, or owner failed, or trivially small response).

    FP_RISK: attacker did not get a successful response.

    Args:
        attacker_meta: The response from the non-owner identity.
        owner_meta: The response from the legitimate owner (may be None).
        diff: The ResponseDiff between attacker and owner.

    Returns:
        Confidence level for this finding.
    """
    if not attacker_meta.is_success:
        return Confidence.FP_RISK

    if owner_meta is None:
        # No owner baseline — can flag but cannot confirm
        return Confidence.POTENTIAL

    if not owner_meta.is_success:
        # Owner also failed — can't establish a usable baseline
        return Confidence.POTENTIAL

    # Both attacker and owner got 2xx — check if attacker got the real resource

    # Identical bodies: strongest signal (attacker got exactly the owner's data)
    if diff.bodies_identical:
        return Confidence.CONFIRMED

    # Same JSON key structure: strong signal (same resource shape)
    if attacker_meta.json_keys and attacker_meta.json_keys == owner_meta.json_keys:
        return Confidence.CONFIRMED

    # Attacker got a non-trivial response body — probable access
    if attacker_meta.body_length > 20:
        return Confidence.POTENTIAL

    return Confidence.POTENTIAL


def score_escalation_confidence(
    *,
    lower_meta: ResponseMeta,
    higher_meta: ResponseMeta | None,
    diff: ResponseDiff,
    is_admin_endpoint: bool,
) -> Confidence:
    """
    Score confidence for a privilege escalation candidate finding.

    CONFIRMED: lower-privileged identity got 2xx on an endpoint where the
    higher-privileged identity also got 2xx, AND the endpoint shows signals
    of being privileged (admin path segment).

    POTENTIAL: lower identity got 2xx but we lack a higher-privilege baseline,
    or the endpoint doesn't strongly signal it's privileged.

    FP_RISK: the lower identity got denied, or the endpoint looks public
    (all identities get identical responses).

    Args:
        lower_meta: Response from the lower-privileged identity.
        higher_meta: Response from the higher-privileged identity (may be None).
        diff: ResponseDiff between lower and higher.
        is_admin_endpoint: True if the endpoint path contains admin-like signals.

    Returns:
        Confidence level for this finding.
    """
    if not lower_meta.is_success:
        return Confidence.FP_RISK

    if higher_meta is None:
        if is_admin_endpoint:
            return Confidence.POTENTIAL
        return Confidence.FP_RISK

    if not higher_meta.is_success:
        # Higher identity also failed — endpoint might be broken or misconfigured
        return Confidence.FP_RISK

    # Both got 2xx
    if is_admin_endpoint:
        return Confidence.CONFIRMED

    # Bodies differ substantially — different content per role
    if abs(diff.length_delta) > 100 or diff.candidate_has_extra_keys:
        return Confidence.POTENTIAL

    # Both got 2xx and responses look identical — endpoint is probably public
    if diff.bodies_identical:
        return Confidence.FP_RISK

    return Confidence.POTENTIAL
