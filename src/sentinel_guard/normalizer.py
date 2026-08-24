import re
import unicodedata
from typing import Tuple

MIN_PROMPT_LEN = 3
MAX_PROMPT_LEN = 1000

INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200B-\u200D\uFEFF\u200E\u200F\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)


def sanitize_invisible_characters(text: str) -> str:
    """Removes zero-width characters, bidi overrides, and binary control bytes."""
    normalized_unicode = unicodedata.normalize("NFC", text)
    return INVISIBLE_CHARS_PATTERN.sub("", normalized_unicode)


def normalize_and_validate(
    raw_text: str, 
    min_len: int = MIN_PROMPT_LEN, 
    max_len: int = MAX_PROMPT_LEN
) -> Tuple[bool, str, str | None]:
    """
    Validates structural bounds and normalizes text into canonical single-spaced format.
    Returns: (is_valid, canonical_text, error_message)
    """
    if not raw_text or not raw_text.strip():
        return False, "", "Input is empty or whitespace-only."

    # 1. Purge invisible and control characters
    cleaned = sanitize_invisible_characters(raw_text)

    # 2. Canonicalize whitespace
    canonical = " ".join(cleaned.split())

    # 3. Check length constraints
    if len(canonical) < min_len:
        return False, canonical, f"Length ({len(canonical)}) below minimum ({min_len})."
    if len(canonical) > max_len:
        return False, canonical, f"Length ({len(canonical)}) exceeds maximum ({max_len})."

    return True, canonical, None