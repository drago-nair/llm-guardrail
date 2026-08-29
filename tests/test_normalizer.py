import pytest
from sentinel_guard.normalizer import (
    normalize_and_validate,
    sanitize_invisible_characters,
)


def test_sanitize_invisible_characters():
    """Verifies zero-width spaces and control bytes are purged."""
    dirty_input = "sec\u200bret\x00_key\uFEFF"
    cleaned = sanitize_invisible_characters(dirty_input)
    assert cleaned == "secret_key"


def test_valid_standard_prompt():
    """Verifies a standard valid prompt passes canonicalization."""
    raw_prompt = "   How   does  machine   learning\nwork?  "
    is_valid, canonical, error = normalize_and_validate(raw_prompt)
    
    assert is_valid is True
    assert canonical == "How does machine learning work?"
    assert error is None


def test_empty_or_whitespace_prompt():
    """Verifies empty strings or pure whitespace fail validation."""
    is_valid, canonical, error = normalize_and_validate("   \n\t  ")
    assert is_valid is False
    assert canonical == ""
    assert "Input is empty or whitespace-only" in error


@pytest.mark.parametrize(
    "payload, expected_valid",
    [
        ("ab", False),               # 2 chars: below min (3)
        ("abc", True),               # 3 chars: exact min
        ("A" * 1000, True),          # 1000 chars: exact max
        ("A" * 1001, False),         # 1001 chars: above max (1000)
    ]
)
def test_length_boundaries(payload, expected_valid):
    """Tests exact boundary conditions using parameterization."""
    is_valid, _, error = normalize_and_validate(payload)
    assert is_valid == expected_valid
    if not expected_valid:
        assert "Length" in error