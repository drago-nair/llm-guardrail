# 🛡️ LLM Guardrail

LLM Guardrail is a CPU-only, six-gate security pipeline that sits in front of a Large Language Model, inspecting every prompt before it reaches the model and masking sensitive data on the way in. It's exposed over a local HTTP API and ships with a self-contained browser extension so anyone — not just developers — can check a prompt before pasting it into any LLM tool.

> **Status: v1.0.0.** All six gates are implemented, wired end-to-end, covered by 116 automated tests, and verified live through the browser extension against a real jailbreak prompt.

## Engineering highlights

- **Defense in depth, cheapest-first.** Six independent gates, ordered so the common case (keyword-level attacks) never pays for loading a transformer model; bypassing the whole pipeline means defeating all six, not just one.
- **Fail-closed by default.** Every gate, and the API's auth layer, blocks the request on any internal error instead of silently letting it through — the safe side of ambiguity is chosen everywhere, not just in the happy path.
- **Calibrated, not guessed.** Gate 6's ALLOW/REVIEW/BLOCK thresholds come from scoring a hand-labeled attack dataset, not an arbitrary cutoff — and the thresholds are overridable per call rather than hardcoded.
- **Reversible PII masking.** Sensitive data is tokenized before it ever reaches a model or a log file, with a request-scoped vault that can restore the real values afterward via `/restore`.
- **Built as a product, not just a library.** A FastAPI service plus a self-contained browser extension — deliberately not a DOM-scraper of one chat site, so it keeps working regardless of which LLM tool someone actually uses.
- **116 tests, fast by design.** Test doubles (fake tokenizers/models/shields via `typing.Protocol`) isolate pipeline-logic tests from the two real transformer models, so the suite runs in seconds, not minutes.

## How a prompt gets checked

A prompt passes through six gates, in order, cheapest first. Any gate can reject the prompt outright; a gate erroring out blocks the request rather than letting it through (fail-closed):

1. **Normalizer** — Unicode NFKC normalization, invisible/zero-width character removal, length validation.
2. **Obfuscation Decoder** — recursively decodes Base64/hex payloads (bounded depth and size) so hidden attacks can't slip past the later gates.
3. **Keyword Shield** — boundary-aware matching against known attack phrases.
4. **PII Engine** — masks emails, phone numbers, SSNs, Aadhaar numbers (Luhn/Verhoeff-checked), credit cards, and API keys behind reversible, request-scoped tokens.
5. **Semantic Shield** — a CPU MiniLM model compares the prompt against known attack-intent embeddings via cosine similarity.
6. **Classifier Shield** — a fine-tuned transformer (Prompt Guard) scores the prompt for prompt-injection intent; scores are converted into an ALLOW / REVIEW / BLOCK decision by a calibrated, overridable threshold policy.

## 🧠 Design notes

### The problem

Every company putting an LLM in front of employees or customers inherits a new attack surface: prompt injection, jailbreaks, and accidental leakage of sensitive data into a model's context window. Most defenses either rely on the model itself to "just refuse" (unreliable, and invisible when it fails), or bolt on a single keyword blocklist (trivially bypassed with encoding or rephrasing). LLM Guardrail takes a different approach: layer several cheap, independent checks in front of the model, each catching a different class of attack, so that bypassing the whole pipeline requires defeating all of them at once.

### Why six gates, in this order

Each gate is ordered from cheapest to most expensive, and any gate can reject a prompt outright — a design borrowed from how network firewalls stack rules, applied to text:

1. **Normalizer** strips the tricks that hide an attack from everything downstream: Unicode normalization collapses visually-identical character variants, and invisible/zero-width characters (a classic way to split up a banned phrase so naive string matching misses it) are removed before anything else runs.
2. **Obfuscation Decoder** recursively unwraps Base64/hex payloads, because an attacker who can't say "ignore previous instructions" directly will just base64-encode it instead. Depth and size limits keep this from being a resource-exhaustion vector in its own right.
3. **Keyword Shield** is the cheapest real check — boundary-aware matching against known attack phrases. It costs microseconds, so it runs before anything that needs a model loaded, catching the large fraction of attacks that don't bother being subtle.
4. **PII Engine** masks sensitive data — emails, phone numbers, SSNs, Aadhaar numbers (validated via the Verhoeff checksum algorithm, not just a regex shape match), credit cards, API keys — behind reversible, request-scoped tokens *before* the prompt is allowed anywhere near a model or a log file.
5. **Semantic Shield** is the first gate that needs a loaded model: a CPU MiniLM sentence embedding compares the prompt's meaning against known attack-intent examples via cosine similarity. This catches attacks that don't share any exact wording with anything in the keyword list.
6. **Classifier Shield** runs a fine-tuned transformer (Prompt Guard) purpose-built for prompt-injection detection, calibrated against a hand-labeled dataset into a three-way ALLOW / REVIEW / BLOCK decision rather than a binary cutoff — because in practice, "soft" jailbreak phrasing (e.g. roleplay-based prompts) scores meaningfully lower than direct override language, and collapsing that into one threshold either over-blocks or under-blocks one category.

Running the cheap gates first isn't just an optimization — it means the *common* case (keyword-level attacks) never pays the cost of loading two transformer models, while still falling back to them for attacks that need more than string matching to catch.

### Fail-closed, everywhere

Every gate is wrapped so that an internal error — a model failing to load, an unexpected exception — results in the request being **blocked**, not quietly allowed through. In a security pipeline, "the classifier crashed so we let it through" is a worse failure mode than over-blocking, so the whole system is built to assume the safe side of every ambiguous outcome.

### From library to product

The six gates started as a pure Python pipeline with no way to actually use it. Two decisions shaped how it became something a non-developer could use:

- **A FastAPI wrapper** (`/check`, `/restore`, `/health`) turns the pipeline into a local service any client can call — the integration boundary between the Python logic and anything else (a script, a browser extension, a future Slack bot).
- **A self-contained browser extension**, deliberately *not* a content script reading a specific chat site's DOM. Intercepting one site's input box is fragile (sites change their internal HTML/React structure without warning) and ties the tool to a single vendor. Instead, the extension is its own popup: paste a prompt, get a verdict, copy the cleaned result into whatever LLM tool you actually use. Less flashy than live DOM interception, but it's the version that still works after any given chat site redesigns itself.

### Hardening before calling it done

Before tagging v1.0.0, three gaps were closed that a "it works on my laptop" demo doesn't need but a real deployment would:

- **API-key auth**, fail-closed the same way the gates are — an unconfigured or mismatched key blocks the request rather than defaulting open.
- **Outbound PII restoration** (`/restore`) — the PII masking was one-way until this was wired in; now a masked token that an LLM echoes back in its reply can be restored to the real value before the employee sees it.
- **JSON-lines audit logging** — every verdict is appended to a durable log, because a security tool that can't answer "what did it block yesterday at 3pm" isn't one a security team could actually run.

### Testing approach

116 tests, built around test *doubles* rather than mocking framework magic — fake tokenizers, fake models, and fake shields that implement the same interface as the real ones (via `typing.Protocol`), so the orchestrator's control flow (which gate ran, in what order, what happens on each verdict) can be tested in milliseconds without loading two transformer models per test. The handful of tests that do exercise the real models are deliberately kept separate, so the fast suite stays fast.

### What this doesn't do (yet)

Built as a time-boxed portfolio project, not a production multi-tenant service — no rate limiting, no centralized config file, no containerized deployment, no dedicated red-team benchmark suite, and the API key is a single shared secret rather than per-user credentials. These are documented gaps, not oversights — see the "Known limitations" section below.

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
