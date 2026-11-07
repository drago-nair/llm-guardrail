import pytest

from sentinel_guard.classifier_policy import (
    DEFAULT_ALLOW_BELOW,
    DEFAULT_BLOCK_AT_OR_ABOVE,
    PolicyDecision,
    decide,
)


def test_low_score_allows():
    """A score well below allow_below is ALLOW."""
    result = decide(0.0018)
    assert isinstance(result, PolicyDecision)
    assert result.decision == "ALLOW"


def test_high_score_blocks():
    """A score well above block_at_or_above is BLOCK."""
    result = decide(0.9977)
    assert result.decision == "BLOCK"


def test_mid_score_reviews():
    """A score between the two thresholds is REVIEW."""
    result = decide(0.0531)
    assert result.decision == "REVIEW"


def test_just_below_allow_threshold_allows():
    """A score just under allow_below still counts as ALLOW."""
    result = decide(DEFAULT_ALLOW_BELOW - 0.0001)
    assert result.decision == "ALLOW"


def test_exactly_at_allow_threshold_reviews():
    """allow_below itself is not ALLOW -- the boundary belongs to REVIEW."""
    result = decide(DEFAULT_ALLOW_BELOW)
    assert result.decision == "REVIEW"


def test_just_below_block_threshold_reviews():
    """A score just under block_at_or_above is still REVIEW, not BLOCK."""
    result = decide(DEFAULT_BLOCK_AT_OR_ABOVE - 0.0001)
    assert result.decision == "REVIEW"


def test_exactly_at_block_threshold_blocks():
    """block_at_or_above itself is BLOCK -- the boundary belongs to BLOCK."""
    result = decide(DEFAULT_BLOCK_AT_OR_ABOVE)
    assert result.decision == "BLOCK"


def test_custom_thresholds_override_defaults():
    """Per-call thresholds change the verdict without editing module defaults."""
    # 0.40 sits in the default REVIEW band, but a stricter block_at_or_above
    # of 0.35 should push it into BLOCK instead.
    result = decide(0.40, block_at_or_above=0.35)
    assert result.decision == "BLOCK"
    assert result.block_at_or_above == 0.35
    # The module-level defaults themselves must be untouched.
    assert DEFAULT_BLOCK_AT_OR_ABOVE == 0.5


def test_invalid_threshold_order_raises():
    """allow_below greater than block_at_or_above leaves no valid REVIEW band."""
    with pytest.raises(ValueError):
        decide(0.2, allow_below=0.9, block_at_or_above=0.1)
