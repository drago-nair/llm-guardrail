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


def check_keywords(
    text: str, 
    blocked_terms: Set[str] = DEFAULT_BLOCKED_KEYWORDS
) -> List[str]:
    """
    Scans text for hard-blocked adversarial phrases.
    Returns a list of all matched keywords.
    """
    lowered = text.lower()
    return [term for term in blocked_terms if term in lowered]