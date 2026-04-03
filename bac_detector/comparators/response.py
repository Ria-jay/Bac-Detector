"""
Response comparison utilities.

Pure functions that compare two ResponseMeta objects and return
structured difference information. These are the building blocks
the detectors use to decide whether an anomaly is present.

All functions return plain values — no side effects, no logging.
"""

from __future__ import annotations

from dataclasses import dataclass

from bac_detector.models.response_meta import ResponseMeta


@dataclass(frozen=True)
class ResponseDiff:
    """
    The result of comparing two ResponseMeta objects.

    Produced by compare_responses() and consumed by the detectors.
    All fields express differences between the `candidate` (the identity
    under test) and the `reference` (the baseline or another identity).
    """

    # Status code comparison
    status_differs: bool
    candidate_status: int
    reference_status: int

    # Body hash comparison — True means the bodies are different
    body_differs: bool

    # Body length difference in bytes (candidate - reference)
    length_delta: int

    # JSON key structure comparison
    # True if the candidate has JSON keys the reference does not
    candidate_has_extra_keys: bool
    # Keys present in candidate but not in reference
    extra_keys: list[str]
    # True if the reference has JSON keys the candidate does not
    # (candidate got less data — possibly truncated/filtered, or different resource)
    candidate_missing_keys: bool
    missing_keys: list[str]

    # Candidate got a success where reference got a denial (4xx)
    success_where_reference_denied: bool

    # Both responses have identical body hashes AND both are real responses
    # (status > 0). Strong signal of shared content — same resource data.
    bodies_identical: bool

    @property
    def is_suspicious(self) -> bool:
        """
        True if any comparison dimension suggests a possible access anomaly.

        Used as a quick pre-filter before detailed scoring.
        """
        return (
            self.success_where_reference_denied
            or self.candidate_has_extra_keys
            or (self.status_differs and self.candidate_status < self.reference_status)
        )


def compare_responses(
    candidate: ResponseMeta,
    reference: ResponseMeta,
) -> ResponseDiff:
    """
    Compare a candidate response against a reference response.

    The candidate is the identity under test (potentially the attacker).
    The reference is what the legitimate owner or a higher-privileged
    identity received.

    Args:
        candidate: The response from the identity being tested.
        reference: The reference response to compare against.

    Returns:
        ResponseDiff capturing all detected differences.
    """
    candidate_ok = candidate.status_code > 0
    reference_ok = reference.status_code > 0

    status_differs = candidate.status_code != reference.status_code
    body_differs = candidate.body_hash != reference.body_hash

    # bodies_identical requires BOTH responses to be real (no error/dry-run)
    # and to have the same body hash.
    bodies_identical = (
        candidate_ok
        and reference_ok
        and candidate.body_hash == reference.body_hash
    )

    length_delta = candidate.body_length - reference.body_length

    # JSON key analysis
    candidate_keys = set(candidate.json_keys)
    reference_keys = set(reference.json_keys)
    extra_keys = sorted(candidate_keys - reference_keys)
    missing_keys = sorted(reference_keys - candidate_keys)

    # The most important signal: candidate got a 2xx where reference got 4xx
    success_where_reference_denied = (
        candidate_ok
        and reference_ok
        and candidate.is_success
        and reference.is_access_denied
    )

    return ResponseDiff(
        status_differs=status_differs,
        candidate_status=candidate.status_code,
        reference_status=reference.status_code,
        body_differs=body_differs,
        length_delta=length_delta,
        candidate_has_extra_keys=bool(extra_keys),
        extra_keys=extra_keys,
        candidate_missing_keys=bool(missing_keys),
        missing_keys=missing_keys,
        success_where_reference_denied=success_where_reference_denied,
        bodies_identical=bodies_identical,
    )


def responses_look_equivalent(a: ResponseMeta, b: ResponseMeta) -> bool:
    """
    Return True if two responses appear to be the same resource.

    Uses a composite check: same status code, identical body hash,
    and both are real responses (not errors).

    Args:
        a: First response.
        b: Second response.

    Returns:
        True if the responses appear to represent the same resource data.
    """
    if a.status_code != b.status_code:
        return False
    if not a.is_success:
        return False
    if a.status_code == 0 or b.status_code == 0:
        return False
    return a.body_hash == b.body_hash


def is_likely_nondeterministic(responses: list[ResponseMeta]) -> bool:
    """
    Heuristic: detect if responses for the SAME resource appear non-deterministic.

    Non-deterministic responses (e.g. containing timestamps, request IDs, or
    random tokens) will have different body hashes even though they represent
    the same underlying resource. These cause false positives when we rely on
    body-hash comparison.

    This function should be called with responses that are all for the SAME
    object_id (or the same endpoint with no object ID) so that natural
    per-object differences are not misidentified as non-determinism.

    We flag as non-deterministic when ALL successful responses have:
      - the same status code
      - the same JSON key structure
      - all-different body hashes

    This pattern indicates the content is structurally stable but value-varying
    (timestamps, request IDs, nonces, etc.).

    Args:
        responses: List of ResponseMeta, all for the same resource/object_id.

    Returns:
        True if responses appear non-deterministic.
    """
    if len(responses) < 2:
        return False

    success_responses = [r for r in responses if r.is_success]
    if len(success_responses) < 2:
        return False

    first = success_responses[0]
    all_same_status = all(r.status_code == first.status_code for r in success_responses)
    all_same_keys = all(r.json_keys == first.json_keys for r in success_responses)
    all_different_hashes = len({r.body_hash for r in success_responses}) == len(success_responses)

    return all_same_status and all_same_keys and all_different_hashes
