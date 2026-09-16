# Prompt Injection Detector (v3)

A machine learning system for detecting prompt injection attacks in LLM-integrated applications, built as a final year B.Tech Cyber Security project.

**Live demo:** https://prompt-injection-detector-nine.vercel.app
(Detector UI at `/`, protected-chatbot demo at `/chat-page`, API docs at `/docs`.)

## Overview

Large Language Models integrated into real applications (chatbots, coding assistants, browser agents) are vulnerable to prompt injection -- attacks where malicious input overrides the model's intended instructions. This project builds a lightweight middleware classifier that screens prompts **before** they reach an LLM, blocking or flagging likely injection attempts in real time.

The v3 detector is **model-agnostic**: the same shield sits in front of ChatGPT, Qwen, Llama, DeepSeek, or any OpenAI-compatible endpoint -- the protected chat demo lets you demonstrate this live.

## Key results (v3)

| Evaluation | Result |
|---|---|
| Held-out test verdict accuracy (3-way verdicts) | **97.6%** |
| Held-out test AUROC | 0.9985 |
| Curated adversarial set -- attacks flagged | **30/30 (100%)** |
| Curated adversarial set -- benign allowed | **29/29 (100%)** |
| Fresh edge-case sweep (novel phrasings) | ~94-100% |
| Live API stress test (28 cases, local & deployed) | **100%** |

## Architecture

```
user prompt ──> [ v3 Detector ] ──ALLOW──> LLM (ChatGPT / Qwen / Llama / DeepSeek ...)
                     │                        ^ system prompt + secrets stay protected
                     ├──FLAG──> passed with warning banner (human in the loop)
                     └──BLOCK──> request never reaches the model
```

**Detection pipeline (v3):**
1. **Word TF-IDF** (unigrams + bigrams) -- phrasing-level signals.
2. **Character TF-IDF** (2-5 grams) -- catches leetspeak, obfuscation, misspellings.
3. **39 heuristic features** -- categorized attack lexicons (override, persona, system-prompt probes, exfiltration, encoding, false authority, urgency, delimiters), high-precision regexes, inverted-index fuzzy matching against canonical jailbreak phrases (rapidfuzz), and obfuscation detectors (zero-width chars, homoglyphs, letter-spelling).
4. **Calibrated ensemble** -- LinearSVC (CalibratedClassifierCV) + LogisticRegression, features scaled.
5. **Explainable guardrails** -- concept-question cap (questions *about* security topics are allowed), harmless-roleplay cap, advice-question cap, and a hard-attack floor (override+system combos, exfiltration, spelled-out attacks, guardrail-disable directives force FLAG/BLOCK).
6. **Threshold tuning** -- BLOCK/FLAG thresholds chosen on validation to maximize 3-way verdict accuracy.

Training data: ~17k labeled prompts from 3 public datasets (deepset prompt-injections, safeguard, jayavibhav) + 2.2k synthetic adversarial augmentations.

## Model-agnostic LLM providers

`/chat` auto-detects the configured provider from environment variables -- all speak the OpenAI chat protocol:

| Provider | Env var | Default model |
|---|---|---|
| OpenAI / ChatGPT | `OPENAI_API_KEY` | gpt-4o-mini |
| Qwen (DashScope) | `QWEN_API_KEY` | qwen-plus |
| Groq (Llama / GPT-OSS) | `GROQ_API_KEY` | resolved dynamically |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| OpenRouter | `OPENROUTER_API_KEY` | openrouter/auto |
| Together AI | `TOGETHER_API_KEY` | Llama-3-8b |
| Any OpenAI-compatible endpoint | `CUSTOM_LLM_URL` + `CUSTOM_LLM_KEY` | `CUSTOM_LLM_MODEL` |

Groq note: model IDs rotate frequently, so the app resolves the best available chat model from the account's `/models` list at request time and falls back through a preference list if a model is rejected -- the demo never dead-ends mid-presentation.

The deployed instance uses **Groq** (`GROQ_API_KEY` set as a Vercel env var) and currently serves `openai/gpt-oss-120b`. To demo with ChatGPT or Qwen instead, add their API key in the Vercel dashboard -- the detector is untouched, only the model behind it changes.

## API

| Endpoint | Description |
|---|---|
| `POST /check` | `{\"text\": ...}` -> verdict (ALLOW/FLAG/BLOCK), probability, thresholds, explainable signals |
| `POST /batch-check` | Screen up to 100 texts at once |
| `POST /chat` | Protected chat: screens the message, forwards to the configured LLM |
| `GET /providers` | Which provider/model is active |
| `GET /chat-page` | Protected chatbot demo UI |
| `GET /` | Detector playground UI |

## Chrome extension

`extension/` contains a Manifest V3 extension that checks any prompt typed into ChatGPT, Claude, Gemini, Qwen (chat.qwen.ai), DeepSeek, Copilot, Mistral, or Grok before you send it -- floating button + auto-check on send, verdict banner with probability and signals. Load it via `chrome://extensions` -> Developer mode -> Load unpacked.

## Local setup

```bash
python -m venv venv
venv/Scripts/pip install -r requirements.txt      # Windows; linux: venv/bin/pip
venv/Scripts/python scripts/unify_data.py          # build training data
venv/Scripts/python scripts/train_v3.py            # train + evaluate + save artifacts
venv/Scripts/python scripts/copy_models_to_api.py  # copy artifacts for Vercel
venv/Scripts/python -m uvicorn app:app --port 8000
venv/Scripts/python scripts/stress_test_v3.py      # 28-case live accuracy report
```

`app.py` reads `.env` for provider keys locally; on Vercel use dashboard/CLI env vars.

## Deployment (Vercel)

- `api/index.py` -- serverless entry exposing the FastAPI app.
- `vercel.json` -- Python 3.12 runtime, model artifacts bundled via `includeFiles`.
- Model artifacts (~4 MB total) are copied into `api/models/` by `scripts/copy_models_to_api.py` -- rerun it after retraining, then `vercel --prod`.
- Required env var for the chat demo: `GROQ_API_KEY` (or any other provider key).

## Project layout

```
app.py                  FastAPI app (detector + protected chat + provider layer)
detector.py             Shared featurization + guardrails (training & inference)
scripts/train_v3.py     Training, augmentation, threshold tuning, evaluation
scripts/stress_test_v3.py  Live 28-case accuracy report (local or deployed URL)
api/index.py + vercel.json  Vercel serverless deployment
static/                 Detector playground + protected chat UI
extension/              Chrome extension for major AI chat sites
models/                 Trained v3 artifacts (committed, ~4 MB)
data/                   Training datasets (gitignored)
```
