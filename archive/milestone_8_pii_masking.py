# ========================================================
# Project: LLM Guardrail Security Engine
# Milestone 8: PII Redaction & Tokenization Engine
# ========================================================

import re
from typing import Dict, Tuple

# Pre-compiled Regex Signatures (from Milestone 7)
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
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
    ),
    "API_KEY": re.compile(
        r"\b(?:sk-[a-zA-Z0-9]{20,48}|ghp_[a-zA-Z0-9]{36})\b"
    )
}


def mask_pii_reversible(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Scans text for sensitive PII and replaces instances with indexed tokens.
    Returns:
        anonymized_text (str): Safe prompt ready for LLM consumption.
        vault (dict): Reversible mapping table (token -> original_value).
    """
    anonymized_text = text
    vault: Dict[str, str] = {}
    counters: Dict[str, int] = {key: 0 for key in PII_PATTERNS.keys()}

    for pii_type, pattern in PII_PATTERNS.items():
        # Find all unique matches to prevent index collisions
        matches = pattern.findall(anonymized_text)
        
        for match in set(matches):
            counters[pii_type] += 1
            token = f"<{pii_type}_{counters[pii_type]}>"
            
            # Store in vault for optional de-masking later
            vault[token] = match
            
            # Replace actual sensitive data with token placeholder
            anonymized_text = anonymized_text.replace(match, token)

    return anonymized_text, vault


def unmask_text(anonymized_text: str, vault: Dict[str, str]) -> str:
    """
    Reconstructs the original text by restoring tokens from the vault.
    """
    restored_text = anonymized_text
    for token, original_value in vault.items():
        restored_text = restored_text.replace(token, original_value)
    return restored_text


# Test Scenarios
sample_prompts = [
    "Send an invoice to alice@company.com and cc support@company.com.",
    "User profile: Phone is 555-123-4567, SSN is 123-45-6789, Card: 4532015012894721.",
    "My GitHub key is ghp_111122223333444455556666777788889999 for deployment."
]

print("=" * 75)
print("[*] SentinelGuard - Milestone 8: Reversible PII Masking Engine")
print("=" * 75)

for idx, prompt in enumerate(sample_prompts, 1):
    masked, vault_data = mask_pii_reversible(prompt)
    reconstructed = unmask_text(masked, vault_data)
    
    print(f"\n[Test Case {idx}]")
    print(f"  Raw Input    : {prompt}")
    print(f"  Masked (LLM) : {masked}")
    print(f"  Vault Stored : {vault_data}")
    print(f"  Restored Text: {reconstructed}")

print("\n" + "=" * 75)