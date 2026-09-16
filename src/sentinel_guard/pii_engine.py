import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
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
    ),
}

VERHOEFF_MULTIPLICATION_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

VERHOEFF_PERMUTATION_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


@dataclass(frozen=True)
class PIIFinding:
    pii_type: str
    value: str
    validation_method: str | None
    checksum_valid: bool | None


def _digits_only(value: str) -> str:
    return "".join(
        character
        for character in value
        if character.isdigit()
    )


def validate_luhn(value: str) -> bool:
    """Validates a card-like value with the Luhn algorithm."""
    digits = _digits_only(value)

    if not 12 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2

    for index, character in enumerate(digits):
        digit = int(character)

        if index % 2 == parity:
            digit *= 2

            if digit > 9:
                digit -= 9

        checksum += digit

    return checksum % 10 == 0


def validate_verhoeff(value: str) -> bool:
    """Validates an Aadhaar-like value with the Verhoeff algorithm."""
    digits = _digits_only(value)

    if len(digits) != 12 or digits[0] in {"0", "1"}:
        return False

    checksum = 0

    for index, character in enumerate(reversed(digits)):
        checksum = VERHOEFF_MULTIPLICATION_TABLE[checksum][
            VERHOEFF_PERMUTATION_TABLE[index % 8][int(character)]
        ]

    return checksum == 0


def scan_pii_detailed(text: str) -> List[PIIFinding]:
    """Returns PII findings with optional checksum metadata."""
    findings: List[PIIFinding] = []

    for pii_type, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            validation_method: str | None = None
            checksum_valid: bool | None = None

            if pii_type == "CREDIT_CARD":
                validation_method = "luhn"
                checksum_valid = validate_luhn(value)

            elif pii_type == "AADHAAR":
                validation_method = "verhoeff"
                checksum_valid = validate_verhoeff(value)

            findings.append(
                PIIFinding(
                    pii_type=pii_type,
                    value=value,
                    validation_method=validation_method,
                    checksum_valid=checksum_valid,
                )
            )

    return findings


def scan_pii(
    text: str,
) -> Tuple[bool, Dict[str, List[str]]]:
    """Returns PII matches grouped by type."""
    findings: Dict[str, List[str]] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = [
            match.group(0)
            for match in pattern.finditer(text)
        ]

        if matches:
            findings[pii_type] = matches

    return len(findings) == 0, findings


def mask_pii(
    text: str,
) -> Tuple[str, Dict[str, str]]:
    """Masks sensitive values and returns a request-scoped vault."""
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

        anonymized = pattern.sub(
            replace_match,
            anonymized,
        )

    return anonymized, vault


def unmask_text(
    anonymized_text: str,
    vault: Dict[str, str],
) -> str:
    """Restores tokens using a request-scoped vault."""
    restored = anonymized_text

    for token, original_value in vault.items():
        restored = restored.replace(
            token,
            original_value,
        )

    return restored