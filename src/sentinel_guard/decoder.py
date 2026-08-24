import base64
import binascii
import re
from typing import List, Set
from sentinel_guard.keyword_shield import DEFAULT_BLOCKED_KEYWORDS

BASE64_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/]{8,}={0,2}\b")
HEX_CANDIDATE_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){4,}\b")


def try_decode_base64(candidate: str) -> str | None:
    """Safely decodes Base64 candidate if it produces printable UTF-8 text."""
    try:
        pad = len(candidate) % 4
        if pad:
            candidate += "=" * (4 - pad)
        decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        if decoded.isprintable() and len(decoded.strip()) > 0:
            return decoded
    except Exception:
        return None
    return None


def try_decode_hex(candidate: str) -> str | None:
    """Safely decodes Hex candidate if it produces printable UTF-8 text."""
    try:
        decoded = binascii.unhexlify(candidate).decode("utf-8")
        if decoded.isprintable() and len(decoded.strip()) > 0:
            return decoded
    except Exception:
        return None
    return None


def check_obfuscated_threats(
    text: str, 
    blocked_terms: Set[str] = DEFAULT_BLOCKED_KEYWORDS
) -> List[str]:
    """Scans for encoded strings and inspects decoded content against blocklists."""
    found_threats: List[str] = []

    # Check Base64
    for match in BASE64_CANDIDATE_REGEX.findall(text):
        decoded = try_decode_base64(match)
        if decoded:
            lowered = " ".join(decoded.split()).lower()
            for kw in blocked_terms:
                if kw in lowered:
                    found_threats.append(f"Base64-Hidden: '{kw}'")

    # Check Hex
    for match in HEX_CANDIDATE_REGEX.findall(text):
        decoded = try_decode_hex(match)
        if decoded:
            lowered = " ".join(decoded.split()).lower()
            for kw in blocked_terms:
                if kw in lowered:
                    found_threats.append(f"Hex-Hidden: '{kw}'")

    return found_threats