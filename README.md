# 🛡️ Sentinel Guard

Sentinel Guard is a CPU-oriented Python security pipeline that inspects, normalizes, decodes, and anonymizes prompts before they are sent to a Large Language Model (LLM).

> > **Current status:** Educational pre-release. The complete five-gate prompt pipeline is implemented. The Semantic Shield is integrated into the orchestrator with lazy loading, shared model reuse, decoded-payload inspection, and fail-closed error handling.

## 🚦 Current Pipeline

1. **Normalizer** — NFKC normalization, invisible-character removal, whitespace canonicalization, and length validation.
2. **Obfuscation Decoder** — Recursive Base64 and hexadecimal inspection with depth, decoded-size, and payload-count limits.
3. **Keyword Shield** — Case-insensitive, boundary-aware attack-phrase matching.
4. **PII Engine** — Conservative masking, deterministic positional tokens, reversible request-scoped vaulting, and checksum-confidence metadata.
5. **Semantic Shield** — Implemented and tested independently; orchestrator integration is the next milestone.

## ✨ Implemented Protections

- Unicode NFKC canonicalization
- Zero-width and bidirectional-control removal
- Recursive Base64 and hexadecimal decoding
- Fail-closed decoder resource limits
- Boundary-aware keyword detection
- Email, US phone, SSN, Aadhaar-like, credit-card, and API-key masking
- Deterministic PII token numbering
- Luhn and Verhoeff checksum-confidence reporting
- Reversible PII restoration
- CPU-based MiniLM semantic similarity

## 📁 Repository Structure

```text
llm-guardrail/
├── archive/
├── src/
│   └── sentinel_guard/
│       ├── __init__.py
│       ├── decoder.py
│       ├── keyword_shield.py
│       ├── normalizer.py
│       ├── orchestrator.py
│       ├── pii_engine.py
│       └── semantic_shield.py
├── tests/
│   ├── test_decoder.py
│   ├── test_keyword_shield.py
│   ├── test_normalizer.py
│   ├── test_orchestrator.py
│   ├── test_pii_engine.py
│   └── test_semantic_shield.py
├── .python-version
├── pyproject.toml
└── README.md# 🛡️ Sentinel Guard

Sentinel Guard is a CPU-oriented Python security pipeline that inspects, normalizes, decodes, and anonymizes prompts before they are sent to a Large Language Model (LLM).

>  **Current status:** Educational pre-release. The complete five-gate prompt pipeline is implemented. The Semantic Shield is integrated into the orchestrator with lazy loading, shared model reuse, decoded-payload inspection, and fail-closed error handling.

## 🚦 Current Pipeline

1. **Normalizer** — NFKC normalization, invisible-character removal, whitespace canonicalization, and length validation.
2. **Obfuscation Decoder** — Recursive Base64 and hexadecimal inspection with depth, decoded-size, and payload-count limits.
3. **Keyword Shield** — Case-insensitive, boundary-aware attack-phrase matching.
4. **PII Engine** — Conservative masking, deterministic positional tokens, reversible request-scoped vaulting, and checksum-confidence metadata.
5. **Semantic Shield** — Compares the sanitized prompt and decoded payloads against pinned attack-signature embeddings using cosine similarity.

## ✨ Implemented Protections

- Unicode NFKC canonicalization
- Zero-width and bidirectional-control removal
- Recursive Base64 and hexadecimal decoding
- Fail-closed decoder resource limits
- Boundary-aware keyword detection
- Email, US phone, SSN, Aadhaar-like, credit-card, and API-key masking
- Deterministic PII token numbering
- Luhn and Verhoeff checksum-confidence reporting
- Reversible PII restoration
- CPU-based MiniLM semantic similarity

## 📁 Repository Structure

```text
llm-guardrail/
├── archive/
├── src/
│   └── sentinel_guard/
│       ├── __init__.py
│       ├── decoder.py
│       ├── keyword_shield.py
│       ├── normalizer.py
│       ├── orchestrator.py
│       ├── pii_engine.py
│       └── semantic_shield.py
├── tests/
│   ├── test_decoder.py
│   ├── test_keyword_shield.py
│   ├── test_normalizer.py
│   ├── test_orchestrator.py
│   ├── test_pii_engine.py
│   └── test_semantic_shield.py
├── .python-version
├── pyproject.toml
└── README.md

## 🗺️ Next Milestone

**Milestone 19:** Add permanent five-gate integration tests covering semantic rejection, decoded semantic attacks, PII-before-semantic ordering, lazy loading, model reuse, encoded PII, and fail-closed model errors.