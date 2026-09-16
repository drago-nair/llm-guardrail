import re
from typing import Dict, List, Tuple

PII_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "PHONE_US": re.compile(
        r"\b(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\b"
    ),
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    ),
    "AADHAAR": re.compile(
        r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
    ),
    "API_KEY": re.compile(
        r"\b(?:sk-[a-zA-Z0-9]{20,48}|ghp_[a-zA-Z0-9]{36})\b"
    )
}


def scan_pii(text: str) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Scans text and returns detected PII matches categorized by type.

    Returns:
        A tuple containing:
        1. Whether the text is free from recognized PII.
        2. A dictionary containing the detected PII.
    """
    findings: Dict[str, List[str]] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)

        if matches:
            findings[pii_type] = matches

    return len(findings) == 0, findings


def mask_pii(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Replaces sensitive entities with indexed semantic tokens.

    Examples:
        First email  -> <EMAIL_1>
        Second email -> <EMAIL_2>

    Repeated appearances of the same value reuse the same token.

    Returns:
        A tuple containing:
        1. The anonymized text.
        2. The temporary token-to-original-value vault.
    """
    anonymized = text
    vault: Dict[str, str] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        value_to_token: Dict[str, str] = {}
        counter = 0

        def replace_match(match: re.Match[str]) -> str:
            nonlocal counter

            original_value = match.group(0)

            if original_value not in value_to_token:
                counter += 1
                token = f"<{pii_type}_{counter}>"

                value_to_token[original_value] = token
                vault[token] = original_value

            return value_to_token[original_value]

        anonymized = pattern.sub(replace_match, anonymized)

    return anonymized, vault


def unmask_text(
    anonymized_text: str,
    vault: Dict[str, str]
) -> str:
    """
    Restores anonymized tokens using the supplied temporary vault.
    """
    restored = anonymized_text

    for token, original_value in vault.items():
        restored = restored.replace(token, original_value)

    return restored