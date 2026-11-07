from dataclasses import dataclass
from typing import Literal

POLICY_VERSION = "2026-11-07-v1"

Decision = Literal["ALLOW", "REVIEW", "BLOCK"]

# Thresholds picked in Milestone 23 from benchmarks/calibrate_classifier.py:
# - all 8 benign calibration examples scored <= 0.0018.
# - 3 of 8 malicious examples used soft, roleplay-style phrasing
#   ("pretend you have no safety policy", "no exceptions, no filters")
#   and scored as low as 0.0049-0.0531. The model itself has low
#   confidence on these, so no threshold can safely ALLOW them --
#   they land in REVIEW instead of being silently let through.
# - the remaining 5 malicious examples, which used explicit override
#   language ("ignore", "disregard", "forget your guidelines"), scored
#   >= 0.3990, clear of the benign cluster.
DEFAULT_ALLOW_BELOW = 0.01
DEFAULT_BLOCK_AT_OR_ABOVE = 0.5


@dataclass
class PolicyDecision:
    """The ALLOW/REVIEW/BLOCK verdict for one Gate 6 classifier score."""

    decision: Decision
    malicious_score: float
    allow_below: float
    block_at_or_above: float
    policy_version: str = POLICY_VERSION


def decide(
    malicious_score: float,
    allow_below: float = DEFAULT_ALLOW_BELOW,
    block_at_or_above: float = DEFAULT_BLOCK_AT_OR_ABOVE,
) -> PolicyDecision:
    """
    Converts a raw Gate 6 malicious_score into an ALLOW/REVIEW/BLOCK verdict.

    allow_below and block_at_or_above are overridable per call so a
    deployment can tune risk tolerance without editing this function.
    """
    if allow_below > block_at_or_above:
        raise ValueError(
            "allow_below must not be greater than block_at_or_above "
            f"(got allow_below={allow_below}, block_at_or_above={block_at_or_above})"
        )

    if malicious_score < allow_below:
        decision: Decision = "ALLOW"
    elif malicious_score >= block_at_or_above:
        decision = "BLOCK"
    else:
        decision = "REVIEW"

    return PolicyDecision(
        decision=decision,
        malicious_score=malicious_score,
        allow_below=allow_below,
        block_at_or_above=block_at_or_above,
    )
