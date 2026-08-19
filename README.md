# 🛡️ SentinelGuard: LLM Security & Guardrail Engine

A modular Python security layer that inspects, sanitizes, and evaluates incoming prompts and outgoing LLM responses to prevent prompt injections, mask sensitive PII, and enforce output safety.

## 🚀 Key Features
- **Input Sanitization & Normalization:** Strips evasion vectors, trailing whitespace, and irregular delimiters.
- **PII Redaction Engine:** Regex-driven detection and masking of sensitive credentials (SSNs, API keys, emails).
- **Adversarial Input Gate:** Logic-based keyword shield and prompt injection classifier.
- **Validation Pipeline:** Pre-flight and post-flight guardrails for LLM APIs.

## 📁 Project Structure
```text
llm-guardrail/
├── guardrail/                  # Virtual environment (ignored)
├── milestone_4_sanitization.py # String sanitization module
├── test_guardrail.py           # Baseline interpreter test
├── .gitignore                  # Git exclusions
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation