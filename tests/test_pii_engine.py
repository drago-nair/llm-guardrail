import pytest
from sentinel_guard.pii_engine import mask_pii, scan_pii, unmask_text


def test_clean_text_no_pii():
    """Verifies that benign text without PII returns unmodified text and empty vault."""
    clean_input = "Can you describe the architectural principles of zero trust?"
    is_clean, findings = scan_pii(clean_input)
    assert is_clean is True
    assert findings == {}

    anonymized, vault = mask_pii(clean_input)
    assert anonymized == clean_input
    assert vault == {}


@pytest.mark.parametrize(
    "raw_text, pii_type, expected_token",
    [
        ("Contact me at dev@enterprise.io immediately", "EMAIL", "<EMAIL_1>"),
        ("My emergency mobile number is 555-839-2001", "PHONE_US", "<PHONE_US_1>"),
        ("Identity record SSN is 123-45-6789", "SSN", "<SSN_1>"),
        ("Citizen verification card is 4532015012894721", "CREDIT_CARD", "<CREDIT_CARD_1>"),
        ("Leaked OpenAI secret sk-abc123def456ghi789jkl0123456789", "API_KEY", "<API_KEY_1>"),
        ("Leaked GitHub token ghp_111122223333444455556666777788889999", "API_KEY", "<API_KEY_1>"),
        ("My Aadhaar ID is 2345 6789 0123 for KYC update", "AADHAAR", "<AADHAAR_1>"),
        ("Verify Aadhaar number: 3456-7890-1234", "AADHAAR", "<AADHAAR_1>"),
    ]
)
def test_individual_pii_masking(raw_text, pii_type, expected_token):
    """Verifies that individual PII entities are replaced by correct semantic tokens."""
    anonymized, vault = mask_pii(raw_text)
    assert expected_token in anonymized
    assert expected_token in vault
    assert pii_type in expected_token


def test_multiple_entities_and_roundtrip_restoration():
    """Verifies multi-entity redaction, indexing, and bidirectional restoration."""
    original_prompt = (
        "Send logs to alice@corp.com and bob@corp.com. "
        "KYC record: 2345 6789 0123."
    )
    
    # 1. Mask
    anonymized, vault = mask_pii(original_prompt)
    
    # Verify tokens were created
    assert "<EMAIL_1>" in anonymized
    assert "<EMAIL_2>" in anonymized
    assert "<AADHAAR_1>" in anonymized
    assert "alice@corp.com" not in anonymized
    assert "2345 6789 0123" not in anonymized
    
    # Verify vault mappings
    assert "<AADHAAR_1>" in vault
    assert len(vault) == 3
    
    # 2. Unmask
    reconstructed = unmask_text(anonymized, vault)
    assert reconstructed == original_prompt