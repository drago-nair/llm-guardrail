import re
from typing import Dict, List, Tuple

PII_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE_US": re.compile(r"\b(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\b"),
    "SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "API_KEY": re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,48}|ghp_[a-zA-Z0-9]{36})\b")
}


def scan_pii(text: str) -> Tuple[bool, Dict[str, List[str]]]:
    """Scans text and returns detected PII matches categorized by type."""
    findings: Dict[str, List[str]] = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[pii_type] = matches
    return len(findings) == 0, findings


def mask_pii(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Replaces sensitive entities with indexed semantic tokens (<EMAIL_1>, etc.)
    and returns the anonymized text along with the session vault.
    """
    anonymized = text
    vault: Dict[str, str] = {}
    counters = {k: 0 for k in PII_PATTERNS.keys()}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = set(pattern.findall(anonymized))
        for m in matches:
            counters[pii_type] += 1
            token = f"<{pii_type}_{counters[pii_type]}>"
            vault[token] = m
            anonymized = anonymized.replace(m, token)

    return anonymized, vault


def unmask_text(anonymized_text: str, vault: Dict[str, str]) -> str:
    """Restores tokens back to original values from vault mapping."""
    restored = anonymized_text
    for token, original_value in vault.items():
        restored = restored.replace(token, original_value)
    return restored