from threading import Lock
from typing import Dict, List, NamedTuple, Protocol

from sentinel_guard.classifier_policy import decide
from sentinel_guard.decoder import scan_obfuscated_content
from sentinel_guard.keyword_shield import check_keywords
from sentinel_guard.normalizer import normalize_and_validate
from sentinel_guard.pii_engine import mask_pii


class SemanticScanResultLike(Protocol):
    """Minimum semantic result interface required by the orchestrator."""

    is_safe: bool
    similarity_score: float
    matched_signature: str | None
    threshold: float


class SemanticShieldLike(Protocol):
    """Minimum semantic scanner interface required by the orchestrator."""

    def scan(
        self,
        prompt: str,
    ) -> SemanticScanResultLike:
        """Scans one prompt and returns a semantic decision."""
        ...


class ClassifierScanResultLike(Protocol):
    """Minimum classifier result interface required by the orchestrator."""

    model_label: str
    benign_score: float
    malicious_score: float
    confidence: float
    model_name: str
    model_revision: str | None


class ClassifierShieldLike(Protocol):
    """Minimum classifier scanner interface required by the orchestrator."""

    def scan(
        self,
        prompt: str,
    ) -> ClassifierScanResultLike:
        """Scores one prompt and returns raw classifier evidence."""
        ...


class PipelineResult(NamedTuple):
    is_allowed: bool
    processed_prompt: str
    rejection_reason: str | None
    anonymization_vault: Dict[str, str]
    audit_flags: List[str]


_default_semantic_shield: SemanticShieldLike | None = None
_semantic_shield_lock = Lock()

_default_classifier_shield: ClassifierShieldLike | None = None
_classifier_shield_lock = Lock()


def _get_default_semantic_shield() -> SemanticShieldLike:
    """Lazily creates one shared Semantic Shield instance."""
    global _default_semantic_shield

    if _default_semantic_shield is None:
        with _semantic_shield_lock:
            if _default_semantic_shield is None:
                from sentinel_guard.semantic_shield import SemanticShield

                _default_semantic_shield = SemanticShield()

    return _default_semantic_shield


def _get_default_classifier_shield() -> ClassifierShieldLike:
    """Lazily creates one shared Classifier Shield instance."""
    global _default_classifier_shield

    if _default_classifier_shield is None:
        with _classifier_shield_lock:
            if _default_classifier_shield is None:
                from sentinel_guard.classifier_shield import ClassifierShield

                _default_classifier_shield = ClassifierShield()

    return _default_classifier_shield


def run_guardrail_pipeline(
    raw_prompt: str,
    semantic_shield: SemanticShieldLike | None = None,
    classifier_shield: ClassifierShieldLike | None = None,
) -> PipelineResult:
    """
    Executes the six-gate prompt security pipeline.

    Gate 1: Normalize and validate input.
    Gate 2: Decode and inspect obfuscated content.
    Gate 3: Detect direct blocked keywords.
    Gate 4: Mask direct PII and block encoded PII.
    Gate 5: Detect semantic similarity to known attack intents.
    Gate 6: Classify prompt-injection intent and apply ALLOW/REVIEW/BLOCK policy.
    """
    audit_flags: List[str] = []

    # Gate 1: Normalization and validation
    is_valid, canonical_text, validation_error = (
        normalize_and_validate(raw_prompt)
    )

    if not is_valid:
        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=(
                f"Validation Gate: {validation_error}"
            ),
            anonymization_vault={},
            audit_flags=["GATE_VALIDATION_FAILED"],
        )

    # Gate 2: Recursive obfuscation inspection
    decoder_result = scan_obfuscated_content(
        canonical_text
    )

    decoder_failures = (
        decoder_result.threats
        + decoder_result.limit_flags
    )

    if decoder_failures:
        audit_flags.extend(decoder_failures)

        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=(
                f"Obfuscation Gate: {decoder_failures}"
            ),
            anonymization_vault={},
            audit_flags=audit_flags,
        )

    # Gate 3: Direct keyword inspection
    direct_threats = check_keywords(canonical_text)

    if direct_threats:
        audit_flags.extend(
            f"Keyword: '{keyword}'"
            for keyword in direct_threats
        )

        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=(
                f"Keyword Gate: {direct_threats}"
            ),
            anonymization_vault={},
            audit_flags=audit_flags,
        )

    # Gate 4: PII masking
    encoded_pii_count = 0

    for decoded_payload in decoder_result.decoded_payloads:
        _, decoded_vault = mask_pii(
            decoded_payload.decoded_text
        )

        encoded_pii_count += len(decoded_vault)

    if encoded_pii_count:
        audit_flags.append(
            f"ENCODED_PII_BLOCKED "
            f"({encoded_pii_count} entities)"
        )

        return PipelineResult(
            is_allowed=False,
            processed_prompt=canonical_text,
            rejection_reason=(
                "PII Gate: encoded content contains sensitive "
                "data that cannot be safely tokenized in place."
            ),
            anonymization_vault={},
            audit_flags=audit_flags,
        )

    safe_prompt, vault = mask_pii(canonical_text)

    if vault:
        audit_flags.append(
            f"PII_REDACTED ({len(vault)} entities)"
        )

    # Targets inspected by both the semantic (Gate 5) and classifier
    # (Gate 6) shields: the visible prompt plus anything the decoder
    # recovered from obfuscated content.
    scan_targets = [
        (
            "prompt",
            safe_prompt,
        )
    ]

    scan_targets.extend(
        (
            (
                f"decoded_{payload.encoding.lower()}"
                f"_depth_{payload.depth}"
            ),
            payload.decoded_text,
        )
        for payload in decoder_result.decoded_payloads
    )

    # Gate 5: Semantic similarity inspection
    try:
        active_semantic_shield = (
            semantic_shield
            if semantic_shield is not None
            else _get_default_semantic_shield()
        )

        for source, target_text in scan_targets:
            semantic_result = active_semantic_shield.scan(
                target_text
            )

            if not semantic_result.is_safe:
                audit_flags.append(
                    "SEMANTIC_ATTACK_DETECTED "
                    f"(source={source}, "
                    f"score={semantic_result.similarity_score:.4f}, "
                    f"threshold={semantic_result.threshold:.4f})"
                )

                return PipelineResult(
                    is_allowed=False,
                    processed_prompt=safe_prompt,
                    rejection_reason=(
                        "Semantic Gate: prompt matched a "
                        "known attack intent."
                    ),
                    anonymization_vault={},
                    audit_flags=audit_flags,
                )

    except Exception as error:
        audit_flags.append(
            f"SEMANTIC_GATE_ERROR "
            f"({type(error).__name__})"
        )

        return PipelineResult(
            is_allowed=False,
            processed_prompt=safe_prompt,
            rejection_reason=(
                "Semantic Gate: security model unavailable; "
                "request blocked by fail-closed policy."
            ),
            anonymization_vault={},
            audit_flags=audit_flags,
        )

    # Gate 6: Classifier-based attack detection
    try:
        active_classifier_shield = (
            classifier_shield
            if classifier_shield is not None
            else _get_default_classifier_shield()
        )

        for source, target_text in scan_targets:
            classifier_result = active_classifier_shield.scan(
                target_text
            )
            policy_decision = decide(classifier_result.malicious_score)

            if policy_decision.decision == "BLOCK":
                audit_flags.append(
                    "CLASSIFIER_ATTACK_BLOCKED "
                    f"(source={source}, "
                    f"score={classifier_result.malicious_score:.4f})"
                )

                return PipelineResult(
                    is_allowed=False,
                    processed_prompt=safe_prompt,
                    rejection_reason=(
                        "Classifier Gate: prompt classified as a "
                        "prompt-injection attack."
                    ),
                    anonymization_vault={},
                    audit_flags=audit_flags,
                )

            if policy_decision.decision == "REVIEW":
                audit_flags.append(
                    "CLASSIFIER_REVIEW_FLAGGED "
                    f"(source={source}, "
                    f"score={classifier_result.malicious_score:.4f})"
                )

    except Exception as error:
        audit_flags.append(
            f"CLASSIFIER_GATE_ERROR "
            f"({type(error).__name__})"
        )

        return PipelineResult(
            is_allowed=False,
            processed_prompt=safe_prompt,
            rejection_reason=(
                "Classifier Gate: security model unavailable; "
                "request blocked by fail-closed policy."
            ),
            anonymization_vault={},
            audit_flags=audit_flags,
        )

    return PipelineResult(
        is_allowed=True,
        processed_prompt=safe_prompt,
        rejection_reason=None,
        anonymization_vault=vault,
        audit_flags=audit_flags,
    )


def run_deterministic_pipeline(
    raw_prompt: str,
    semantic_shield: SemanticShieldLike | None = None,
    classifier_shield: ClassifierShieldLike | None = None,
) -> PipelineResult:
    """Backward-compatible wrapper for the historical pipeline name."""
    return run_guardrail_pipeline(
        raw_prompt,
        semantic_shield=semantic_shield,
        classifier_shield=classifier_shield,
    )