# ========================================================
# Project: LLM Guardrail Security Engine
# Milestone 7: Regex Structured PII & Secret Detection
# ========================================================

import re
from typing import Dict, List, Tuple

# Pre-compiled regular expressions for structured PII and credentials
PII_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "PHONE_US": re.compile(
        r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"
    ),
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
    ),
    "OPENAI_API_KEY": re.compile(
        r"\bsk-[a-zA-Z0-9]{20,48}\b"
    ),
    "GITHUB_TOKEN": re.compile(
        r"\bghp_[a-zA-Z0-9]{36}\b"
    )
}


def scan_pii(text: str) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Scans text against structured PII and credential signatures.
    Returns:
        is_clean (bool): True if no PII found, False if PII detected.
        findings (dict): Categorized dictionary of detected PII strings.
    """
    findings: Dict[str, List[str]] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            # Flatten tuples if regex contains capturing groups
            flat_matches = [
                "".join(m) if isinstance(m, tuple) else m 
                for m in matches
            ]
            findings[pii_type] = flat_matches

    is_clean = len(findings) == 0
    return is_clean, findings


# Test scenarios with simulated dirty payloads
test_prompts = [
    "What is the best way to deploy a Docker container to AWS?",
    "My email is john.doe@cybersec.org and my mobile number is +1-555-839-2001.",
    "Database leaked SSN 123-45-6789 and Visa card 4532015012894721.",
    "Accidentally committed my token ghp_111122223333444455556666777788889999 to github.",
    "My OpenAI key is sk-abcdef1234567890abcdef1234567890 please keep it safe."
]

print("=" * 75)
print("[*] SentinelGuard - Milestone 7: Regex PII & Secret Detection Engine")
print("=" * 75)

for idx, prompt in enumerate(test_prompts, 1):
    is_clean, detections = scan_pii(prompt)
    verdict = "[CLEAN]" if is_clean else "[PII DETECTED]"
    
    print(f"\n[Scenario {idx}]")
    print(f"  Input  : {prompt}")
    print(f"  Verdict: {verdict}")
    
    if not is_clean:
        for pii_type, matched_values in detections.items():
            print(f"    - {pii_type} ({len(matched_values)} found): {matched_values}")

print("\n" + "=" * 75)