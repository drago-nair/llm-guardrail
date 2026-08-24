from typing import Dict, List, NamedTuple

from sentinel_guard.decoder import check_obfuscated_threats
from sentinel_guard.keyword_shield import check_keywords
from sentinel_guard.normalizer import normalize_and_validate
from sentinel_guard.pii_engine import mask_pii


class PipelineResult(NamedTuple):
    is_allowed: bool
    processed_prompt: str
    rejection_reason: str | None
    anonymization_vault: Dict[str, str]
    audit_flags: List[str]


def run_deterministic_pipeline(raw_prompt: str) -> PipelineResult:
    """
    Executes the Tier-1 deterministic security gate pipeline:
    1. Normalization & structural length validation.
    2. Base64/Hex obfuscation unpacking.
    3. Direct keyword shield evaluation.
    4. PII detection and reversible tokenization.
    """
    audit_flags: List[str] = []

    # Gate 1: Validation
    is_valid, canonical_text, val_error = normalize_and_validate(raw_prompt)
    if not is_valid:
        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=f"Validation Gate: {val_error}",
            anonymization_vault={},
            audit_flags=["GATE_VALIDATION_FAILED"]
        )

    # Gate 2: Obfuscation
    obf_threats = check_obfuscated_threats(canonical_text)
    if obf_threats:
        audit_flags.extend(obf_threats)
        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=f"Obfuscation Gate: {obf_threats}",
            anonymization_vault={},
            audit_flags=audit_flags
        )

    # Gate 3: Keywords
    direct_threats = check_keywords(canonical_text)
    if direct_threats:
        audit_flags.extend([f"Keyword: '{kw}'" for kw in direct_threats])
        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=f"Keyword Gate: {direct_threats}",
            anonymization_vault={},
            audit_flags=audit_flags
        )

    # Gate 4: PII Masking
    safe_prompt, vault = mask_pii(canonical_text)
    if vault:
        audit_flags.append(f"PII_REDACTED ({len(vault)} entities)")

    return PipelineResult(
        is_allowed=True,
        processed_prompt=safe_prompt,
        rejection_reason=None,
        anonymization_vault=vault,
        audit_flags=audit_flags
    )