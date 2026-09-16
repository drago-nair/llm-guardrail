import re
from typing import List, Set

DEFAULT_BLOCKED_KEYWORDS: Set[str] = {
    "ignore all previous instructions",
    "ignore previous instructions",
    "disregard all previous rules",
    "system prompt override",
    "you are now in developer mode",
    "bypass safety filters",
    "dan mode",
    "drop table",
    "delete from users",
    "format c:",
    "rm -rf /"
}


def _compile_keyword_pattern(term: str) -> re.Pattern[str]:
    """
    Builds a safe, case-insensitive regex pattern for a blocked term.

    Word boundaries are added only when the beginning or ending character
    is a normal word character. This preserves symbolic commands such as
    'rm -rf /' and 'format c:'.
    """
    start_boundary = r"(?<!\w)" if re.match(r"\w", term[0]) else ""
    end_boundary = r"(?!\w)" if re.match(r"\w", term[-1]) else ""

    return re.compile(
        f"{start_boundary}{re.escape(term)}{end_boundary}",
        flags=re.IGNORECASE,
    )


def check_keywords(
    text: str,
    blocked_terms: Set[str] = DEFAULT_BLOCKED_KEYWORDS
) -> List[str]:
    """
    Scans text for complete hard-blocked adversarial phrases.

    Returns:
        A list containing every blocked term found in the text.
    """
    matched_terms: List[str] = []

    # Sorting makes the result order consistent between executions.
    for term in sorted(blocked_terms):
        if not term:
            continue

        pattern = _compile_keyword_pattern(term)

        if pattern.search(text):
            matched_terms.append(term)

    return matched_terms