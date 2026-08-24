# ========================================================
# Project: LLM Guardrail Security Engine
# Milestone 5: Input Length & Character Validation Gate
# ========================================================

import re
import unicodedata
from typing import Tuple

# Policy Constraints
MIN_PROMPT_LEN = 3
MAX_PROMPT_LEN = 1000

# Regex pattern matching zero-width characters and ASCII control characters (excluding newline/tab handled in M4)
INVISIBLE_CHARS_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def sanitize_invisible_characters(text: str) -> str:
    """Removes zero-width spaces, bidi overrides, and binary control characters."""
    # Normalize unicode to canonical composition (NFC)
    normalized_unicode = unicodedata.normalize("NFC", text)
    # Strip invisible/malicious control characters
    cleaned_text = INVISIBLE_CHARS_PATTERN.sub("", normalized_unicode)
    return cleaned_text


def validate_input_gate(raw_text: str, min_len: int = MIN_PROMPT_LEN, max_len: int = MAX_PROMPT_LEN) -> Tuple[bool, str, str]:
    """
    Evaluates input integrity and length bounds.
    Returns: (is_valid, cleaned_text_or_empty, reason_message)
    """
    # 1. Null / Empty payload check
    if not raw_text or not raw_text.strip():
        return False, "", "REJECTED: Empty or whitespace-only input received."

    # 2. Strip invisible smuggling characters
    cleaned = sanitize_invisible_characters(raw_text)

    # 3. Collapse whitespace and lower-case (Milestone 4 normalization)
    canonical = " ".join(cleaned.split()).lower()

    # 4. Length Boundary Validation
    input_length = len(canonical)
    if input_length < min_len:
        return False, canonical, f"REJECTED: Payload length ({input_length}) below minimum threshold ({min_len})."
    
    if input_length > max_len:
        return False, canonical, f"REJECTED: Payload length ({input_length}) exceeds maximum limit ({max_len})."

    return True, canonical, "PASSED: Input meets structural policy."


# Adversarial test scenarios
test_cases = [
    ("Valid Prompt", "What are the core fundamentals of cloud security?"),
    ("Empty Prompt", "   \t\n  "),
    ("Short Prompt", "hi"),
    ("Overly Long Prompt", "A" * 1200),
    ("Zero-Width Smuggled Injection", "bypass\u200b \u200cauth\u200d rule"),
    ("Null Byte Injection", "read\x00 secret configuration files")
]

print("=" * 70)
print("[*] SentinelGuard - Milestone 5: Input Validation Gate")
print("=" * 70)

for label, payload in test_cases:
    is_valid, processed, reason = validate_input_gate(payload)
    status_tag = "[ALLOWED]" if is_valid else "[BLOCKED]"
    
    print(f"\nTest Scenario : {label}")
    print(f"Raw Input     : {repr(payload[:60])}{'...' if len(payload) > 60 else ''}")
    print(f"Result        : {status_tag} -> {reason}")
    if is_valid:
        print(f"Clean Output  : {repr(processed)}")

print("\n" + "=" * 70)