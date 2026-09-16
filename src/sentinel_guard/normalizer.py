import re
import unicodedata
from typing import Tuple

MIN_PROMPT_LEN = 3
MAX_PROMPT_LEN = 1000

INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F"
    r"\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]"
)


def sanitize_invisible_characters(text: str) -> str:
    """Applies NFKC and removes zero-width, bidi, and control characters."""
    normalized_unicode = unicodedata.normalize("NFKC", text)
    return INVISIBLE_CHARS_PATTERN.sub("", normalized_unicode)


def normalize_and_validate(
    raw_text: str,
    min_len: int = MIN_PROMPT_LEN,
    max_len: int = MAX_PROMPT_LEN
) -> Tuple[bool, str, str | None]:
    """
    Validates structural bounds and normalizes text into canonical
    single-spaced format.

    Returns:
        (is_valid, canonical_text, error_message)
    """
    if not raw_text or not raw_text.strip():
        return False, "", "Input is empty or whitespace-only."

    # Step 1: Apply NFKC normalization and remove invisible characters.
    cleaned = sanitize_invisible_characters(raw_text)

    # Step 2: Collapse repeated whitespace into single spaces.
    canonical = " ".join(cleaned.split())

    # Step 3: Check the permitted length boundaries.
    if len(canonical) < min_len:
        return (
            False,
            canonical,
            f"Length ({len(canonical)}) below minimum ({min_len})."
        )

    if len(canonical) > max_len:
        return (
            False,
            canonical,
            f"Length ({len(canonical)}) exceeds maximum ({max_len})."
        )

    return True, canonical, None