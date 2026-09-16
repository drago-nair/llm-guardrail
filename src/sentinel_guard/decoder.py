import base64
import binascii
import re
from collections import deque
from dataclasses import dataclass
from typing import List, Set, Tuple

from sentinel_guard.keyword_shield import (
    DEFAULT_BLOCKED_KEYWORDS,
    check_keywords,
)
from sentinel_guard.normalizer import sanitize_invisible_characters

BASE64_CANDIDATE_REGEX = re.compile(
    r"\b[A-Za-z0-9+/]{8,}={0,2}\b"
)

HEX_CANDIDATE_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{2}){4,}\b"
)

MAX_DECODE_DEPTH = 3
MAX_DECODED_BYTES = 4096
MAX_DECODED_PAYLOADS = 20


@dataclass
class DecodedPayload:
    """One successfully decoded and normalized payload."""

    encoding: str
    decoded_text: str
    depth: int


@dataclass
class DecoderScanResult:
    """Structured result produced by the obfuscation scanner."""

    threats: List[str]
    decoded_payloads: List[DecodedPayload]
    limit_flags: List[str]


def _decode_readable_utf8(
    decoded_bytes: bytes,
    max_decoded_bytes: int,
) -> str | None:
    """Returns readable UTF-8 text when the byte payload is within limits."""
    if len(decoded_bytes) > max_decoded_bytes:
        return None

    try:
        decoded_text = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    sanitized_text = sanitize_invisible_characters(decoded_text)

    contains_only_readable_characters = all(
        character.isprintable() or character in "\n\r\t"
        for character in sanitized_text
    )

    if not sanitized_text.strip():
        return None

    if not contains_only_readable_characters:
        return None

    return decoded_text


def try_decode_base64(
    candidate: str,
    max_decoded_bytes: int = MAX_DECODED_BYTES,
) -> str | None:
    """Safely decodes Base64 containing readable UTF-8 text."""
    try:
        padded_candidate = candidate
        missing_padding = len(padded_candidate) % 4

        if missing_padding:
            padded_candidate += "=" * (4 - missing_padding)

        decoded_bytes = base64.b64decode(
            padded_candidate,
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    return _decode_readable_utf8(
        decoded_bytes,
        max_decoded_bytes,
    )


def try_decode_hex(
    candidate: str,
    max_decoded_bytes: int = MAX_DECODED_BYTES,
) -> str | None:
    """Safely decodes hexadecimal containing readable UTF-8 text."""
    try:
        decoded_bytes = binascii.unhexlify(candidate)
    except (binascii.Error, ValueError):
        return None

    return _decode_readable_utf8(
        decoded_bytes,
        max_decoded_bytes,
    )


def _normalize_decoded_text(decoded_text: str) -> str:
    """Applies the same Unicode and whitespace protections as Gate 1."""
    sanitized = sanitize_invisible_characters(decoded_text)

    return " ".join(sanitized.split())


def _extract_candidates(text: str) -> List[Tuple[int, str, str]]:
    """Returns encoded candidates in their original left-to-right order."""
    candidates: List[Tuple[int, str, str]] = []

    for match in BASE64_CANDIDATE_REGEX.finditer(text):
        candidates.append(
            (
                match.start(),
                "Base64",
                match.group(0),
            )
        )

    for match in HEX_CANDIDATE_REGEX.finditer(text):
        candidates.append(
            (
                match.start(),
                "Hex",
                match.group(0),
            )
        )

    return sorted(
        candidates,
        key=lambda item: (item[0], item[1]),
    )


def _decode_candidate(
    encoding: str,
    candidate: str,
    max_decoded_bytes: int,
) -> str | None:
    """Routes a candidate to its matching decoder."""
    if encoding == "Base64":
        return try_decode_base64(
            candidate,
            max_decoded_bytes,
        )

    return try_decode_hex(
        candidate,
        max_decoded_bytes,
    )


def _estimate_decoded_size(
    encoding: str,
    candidate: str,
) -> int:
    """Estimates decoded bytes without allocating the decoded payload."""
    if encoding == "Hex":
        return len(candidate) // 2

    unpadded_length = len(candidate.rstrip("="))

    complete_groups, remainder = divmod(
        unpadded_length,
        4,
    )

    return (
        complete_groups * 3
    ) + max(
        0,
        remainder - 1,
    )


def _contains_decodable_child(
    text: str,
    max_decoded_bytes: int,
) -> bool:
    """Checks whether an encoded layer exists beyond the depth limit."""
    for _, encoding, candidate in _extract_candidates(text):
        estimated_size = _estimate_decoded_size(
            encoding,
            candidate,
        )

        if estimated_size > max_decoded_bytes:
            return True

        decoded = _decode_candidate(
            encoding,
            candidate,
            max_decoded_bytes,
        )

        if decoded is not None:
            return True

    return False


def scan_obfuscated_content(
    text: str,
    blocked_terms: Set[str] = DEFAULT_BLOCKED_KEYWORDS,
    max_depth: int = MAX_DECODE_DEPTH,
    max_decoded_bytes: int = MAX_DECODED_BYTES,
    max_payloads: int = MAX_DECODED_PAYLOADS,
) -> DecoderScanResult:
    """Recursively decodes and inspects Base64 and hexadecimal payloads."""
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1.")

    if max_decoded_bytes < 1:
        raise ValueError(
            "max_decoded_bytes must be at least 1."
        )

    if max_payloads < 1:
        raise ValueError("max_payloads must be at least 1.")

    threats: List[str] = []
    decoded_payloads: List[DecodedPayload] = []
    limit_flags: List[str] = []

    pending_texts = deque(
        [
            (text, 0),
        ]
    )

    seen_candidates: Set[Tuple[str, str]] = set()
    queued_texts: Set[str] = {text}

    while pending_texts:
        current_text, current_depth = pending_texts.popleft()

        for _, encoding, candidate in _extract_candidates(
            current_text
        ):
            candidate_key = (
                encoding,
                candidate,
            )

            if candidate_key in seen_candidates:
                continue

            seen_candidates.add(candidate_key)

            estimated_size = _estimate_decoded_size(
                encoding,
                candidate,
            )

            if estimated_size > max_decoded_bytes:
                limit_flag = (
                    "Decoder-Limit: maximum decoded payload size "
                    f"({max_decoded_bytes} bytes) exceeded."
                )

                if limit_flag not in limit_flags:
                    limit_flags.append(limit_flag)

                continue

            decoded_text = _decode_candidate(
                encoding,
                candidate,
                max_decoded_bytes,
            )

            if decoded_text is None:
                continue

            normalized_text = _normalize_decoded_text(
                decoded_text
            )

            if not normalized_text:
                continue

            if len(decoded_payloads) >= max_payloads:
                limit_flag = (
                    "Decoder-Limit: maximum decoded payload count "
                    f"({max_payloads}) reached."
                )

                limit_flags.append(limit_flag)

                return DecoderScanResult(
                    threats=threats,
                    decoded_payloads=decoded_payloads,
                    limit_flags=limit_flags,
                )

            payload_depth = current_depth + 1

            decoded_payloads.append(
                DecodedPayload(
                    encoding=encoding,
                    decoded_text=normalized_text,
                    depth=payload_depth,
                )
            )

            matched_keywords = check_keywords(
                normalized_text,
                blocked_terms,
            )

            for keyword in matched_keywords:
                threat = (
                    f"{encoding}-Hidden "
                    f"(depth {payload_depth}): "
                    f"'{keyword}'"
                )

                if threat not in threats:
                    threats.append(threat)

            if payload_depth < max_depth:
                if normalized_text not in queued_texts:
                    pending_texts.append(
                        (
                            normalized_text,
                            payload_depth,
                        )
                    )

                    queued_texts.add(normalized_text)

            elif _contains_decodable_child(
                normalized_text,
                max_decoded_bytes,
            ):
                limit_flag = (
                    "Decoder-Limit: maximum recursion depth "
                    f"({max_depth}) reached."
                )

                if limit_flag not in limit_flags:
                    limit_flags.append(limit_flag)

    return DecoderScanResult(
        threats=threats,
        decoded_payloads=decoded_payloads,
        limit_flags=limit_flags,
    )


def check_obfuscated_threats(
    text: str,
    blocked_terms: Set[str] = DEFAULT_BLOCKED_KEYWORDS,
) -> List[str]:
    """Returns threats and safety-limit violations for the orchestrator."""
    result = scan_obfuscated_content(
        text,
        blocked_terms,
    )

    return result.threats + result.limit_flags