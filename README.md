# 🛡️ LLM Guardrail

LLM Guardrail is a CPU-only, six-gate security pipeline that sits in front of a Large Language Model, inspecting every prompt before it reaches the model and masking sensitive data on the way in. It's exposed over a local HTTP API and ships with a self-contained browser extension so anyone — not just developers — can check a prompt before pasting it into any LLM tool.

> **Status: v1.0.0.** All six gates are implemented, wired end-to-end, covered by 116 automated tests, and verified live through the browser extension against a real jailbreak prompt.

## How a prompt gets checked

A prompt passes through six gates, in order, cheapest first. Any gate can reject the prompt outright; a gate erroring out blocks the request rather than letting it through (fail-closed):

1. **Normalizer** — Unicode NFKC normalization, invisible/zero-width character removal, length validation.
2. **Obfuscation Decoder** — recursively decodes Base64/hex payloads (bounded depth and size) so hidden attacks can't slip past the later gates.
3. **Keyword Shield** — boundary-aware matching against known attack phrases.
4. **PII Engine** — masks emails, phone numbers, SSNs, Aadhaar numbers (Luhn/Verhoeff-checked), credit cards, and API keys behind reversible, request-scoped tokens.
5. **Semantic Shield** — a CPU MiniLM model compares the prompt against known attack-intent embeddings via cosine similarity.
6. **Classifier Shield** — a fine-tuned transformer (Prompt Guard) scores the prompt for prompt-injection intent; scores are converted into an ALLOW / REVIEW / BLOCK decision by a calibrated, overridable threshold policy.

## API

Run the server locally:

```bash
export GUARDRAIL_API_KEY="your-own-secret-here"
PYTHONPATH=src:. guardrail/bin/uvicorn sentinel_guard.api:app --host 0.0.0.0 --port 8000
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /check` | `X-API-Key` header | Runs a prompt through all six gates. Returns the verdict, the masked prompt, audit flags, and the PII vault needed to reverse the masking later. |
| `POST /restore` | `X-API-Key` header | Given text and a vault from `/check`, restores any masked PII tokens back to their real values — used once the LLM's reply comes back. |
| `GET /health` | none | Liveness check. |

The API fails closed: if `GUARDRAIL_API_KEY` isn't set on the server, or a request's key doesn't match, every protected endpoint rejects the request (`401`) rather than silently allowing it through.

Every `/check` call appends one line to `logs/audit.jsonl` (timestamp, verdict, reason, audit flags, masked prompt) — a persistent audit trail of what the pipeline has blocked or allowed.

## Browser extension

`extension/` is a self-contained Manifest V3 popup — it doesn't read or modify any website's DOM, so it works with whatever LLM tool you actually use:

1. Start the API (above).
2. In Chrome/Edge: `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the `extension` folder.
3. Open the popup, enter the same value you set for `GUARDRAIL_API_KEY`, paste a prompt, and click **Check**.

You'll get a green **ALLOWED**, amber **REVIEW**, or red **BLOCKED** badge, plus a cleaned prompt you can copy into your LLM tool of choice.

If the API runs on a different machine on your network, update `API_URL` in `extension/popup.js` and the matching entry in `extension/manifest.json`'s `host_permissions` to that machine's address, and make sure its firewall allows the port from your network.

## Repository structure

```text
llm-guardrail/
├── src/sentinel_guard/
│   ├── api.py                # FastAPI app: /check, /restore, /health
│   ├── audit_log.py          # JSON-lines audit trail
│   ├── normalizer.py         # Gate 1
│   ├── decoder.py            # Gate 2
│   ├── keyword_shield.py     # Gate 3
│   ├── pii_engine.py         # Gate 4 (mask_pii / unmask_text)
│   ├── semantic_shield.py    # Gate 5
│   ├── classifier_shield.py  # Gate 6 (raw model scoring)
│   ├── classifier_policy.py  # Gate 6 (score → ALLOW/REVIEW/BLOCK)
│   └── orchestrator.py       # Wires all six gates together
├── tests/                    # One test file per module above, plus test_api.py
├── benchmarks/               # Latency/memory profiling, classifier calibration
├── extension/                # Browser extension (manifest, popup, icons)
├── pyproject.toml
└── README.md
```

## Setup

```bash
python3 -m venv guardrail
source guardrail/bin/activate
pip install -e ".[dev]"
PYTHONPATH=src:. pytest -q
```

Requires Python 3.12. Runs entirely on CPU — no GPU/CUDA dependency.

## Known limitations

This is a personal/portfolio project, time-boxed to ship a working end-to-end demo rather than a hardened multi-tenant service. Honest gaps if this were to run as a real company-wide deployment:

- No rate limiting — a misbehaving client could hammer the classifier model.
- No centralized config file — policy thresholds are module constants, overridable per call but not via a config file.
- No Dockerfile / containerized deployment yet.
- No dedicated adversarial red-team benchmark suite beyond the hand-labeled calibration set used to tune Gate 6's thresholds.
- The API key is a single shared secret, not per-user credentials.
