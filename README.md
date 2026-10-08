# <img src="static/logo.png" width="46" align="top" alt="PromptShield logo"> Prompt Injection Detector (v3)

![Test accuracy](https://img.shields.io/badge/test%20accuracy-98.26%25-brightgreen)
![AUROC](https://img.shields.io/badge/AUROC-0.9987-blue)
![Red-team attacks caught](https://img.shields.io/badge/red--team%20attacks%20caught-30%2F30-red)
![Live stress test](https://img.shields.io/badge/live%20stress%20test-29%2F29-orange)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-serverless-009688?logo=fastapi&logoColor=white)
![Deployed](https://img.shields.io/badge/deployed-Vercel-black?logo=vercel&logoColor=white)

**A machine-learning firewall for LLM prompts.** Every prompt is screened *before* it reaches the model: a TF‑IDF + 39-heuristic ensemble issues an **ALLOW / FLAG / BLOCK** verdict in milliseconds, catching instruction overrides, roleplay jailbreaks, multi-step social-engineering and system-prompt exfiltration. Every model reply is re-scored by an **output firewall** (canary-token scan + full re-detection) to stop indirect leaks. All events land on a **per-user security dashboard** with criticality ratings and automated **daily / weekly / monthly PDF reports**.

The shield is **model-agnostic** — point it at ChatGPT, Qwen, Llama, DeepSeek or any OpenAI-compatible API and it protects them all identically. The whole app is **login-first**: accounts with PBKDF2-hashed passwords and HMAC-signed sessions, history scoped per user, persisted on Neon Postgres.

Built as a final year B.Tech Cyber Security project.

| 🎯 Detector | 💬 Protected chatbot | 📊 Attack dashboard | 📄 PDF report |
|---|---|---|---|
| [Try it live](https://prompt-injection-detector-nine.vercel.app/) | [Chat demo](https://prompt-injection-detector-nine.vercel.app/chat-page) | [Dashboard](https://prompt-injection-detector-nine.vercel.app/dashboard) | [Daily report](https://prompt-injection-detector-nine.vercel.app/api/report/daily) |

**Demo account:** `demo@promptshield.dev` / `DemoViva#2026` (or create your own)

---

## 📸 Screenshots

**Login-first gate** — every visitor signs in; history and reports are saved to the account.

![Login page](docs/screenshots/login.png)

**Create account** — salted PBKDF2 password hashing, session cookie on signup.

![Signup page](docs/screenshots/signup.png)

**Detector catching a direct override** — BLOCK verdict at 97.5% injection probability, word-level highlights and the full signal breakdown.

![Detector blocking an attack](docs/screenshots/detector-block.png)

**Protected chatbot demo** — the jailbreak is stopped at the input layer; the LLM is never called.

![Chat firewall blocking a jailbreak](docs/screenshots/chat-firewall.png)

**Live attack dashboard (per-user)** — KPIs, criticality and attack-type breakdowns, 14-day timeline and the live event feed, scoped to the signed-in account.

![Per-user attack dashboard](docs/screenshots/dashboard.png)

**Automated PDF security report** — executive summary, attack taxonomy, mitigations and incident log, generated per account ("Prepared for: …").

![PDF daily report page 1](docs/screenshots/report-daily-1.png)
![PDF daily report page 2](docs/screenshots/report-daily-2.png)

---

## 🎯 Key results

| Evaluation | Result |
|---|---|
| Held-out test verdict accuracy (3-way ALLOW/FLAG/BLOCK) | **98.26%** |
| Held-out test AUROC | **0.9987** |
| Curated adversarial red-team set — attacks caught | **30/30 (100%)** |
| Live API stress test (29 cases, local **and** production) | **29/29 (100%)** |
| Multi-step social-engineering scenarios (12 × 4-turn) jailbroken | **0/12** |

The multi-step red-team ([report](docs/MULTISTEP_REDTEAM.md)) escalates from benign pretexts to system-prompt extraction across 4 conversational turns: 8/12 scenarios were stopped by the input-layer detector, the other 4 by the output firewall — no secret ever leaked.

## 🏗️ System architecture

```mermaid
flowchart TB
    U["👤 User browser / Chrome extension"] --> GW["Login-first gate<br/>session cookie required"]
    GW -- "no session: 303 → /login?next=… / 401" --> AUTH["auth.py — signup / login<br/>PBKDF2-SHA256 + HMAC cookie"]
    AUTH --> U
    GW -- "authenticated" --> APP["FastAPI app (Vercel serverless)"]
    APP --> DET["🧠 v3 Detector<br/>TF-IDF ×2 + 39 heuristics + calibrated ensemble"]
    DET -- "ALLOW / FLAG" --> LLM["LLM provider layer<br/>ChatGPT · Qwen · Groq · DeepSeek · any OpenAI-compatible API"]
    DET -- "BLOCK" --> U
    LLM --> OFW["🛡️ Output firewall<br/>canary scan + reply re-scoring"]
    OFW -- "clean reply" --> U
    OFW -- "leak / injection" --> U
    APP -- "every event" --> LOG["attack_log.py"]
    LOG --> PG[("Neon Postgres<br/>persistent, per-user")]
    LOG -. "local dev fallback" .-> SL[("SQLite")]
    LOG --> DASH["Live dashboard + per-user PDF reports"]
    DASH --> U
```

## 🔍 Detection pipeline

```mermaid
flowchart LR
    IN["Prompt text"] --> F1["Word TF-IDF<br/>uni + bigrams"]
    IN --> F2["Char TF-IDF<br/>2-5 grams, catches leetspeak"]
    IN --> F3["39 heuristic signals<br/>lexicons · regexes · fuzzy jailbreak match · obfuscation"]
    F1 --> ENS["Calibrated ensemble<br/>LinearSVC + LogisticRegression"]
    F2 --> ENS
    F3 --> ENS
    ENS --> GR["Explainable guardrails<br/>hard-attack floor · concept-question cap · harmless-roleplay cap"]
    GR --> TH["Thresholds<br/>BLOCK ≥ 0.74 · FLAG ≥ 0.72"]
    TH --> B["⛔ BLOCK — never reaches the model"]
    TH --> FL["⚠️ FLAG — human in the loop"]
    TH --> AL["✅ ALLOW — forwarded"]
```

## 🧅 Defense in depth (protected chat)

```mermaid
sequenceDiagram
    participant U as User
    participant D as Detector (input layer)
    participant M as LLM + canary secret
    participant O as Output firewall
    U->>D: message
    D-->>U: BLOCK → LLM never called (input-layer stop)
    D->>M: ALLOW/FLAG forwarded with canary-tagged system prompt
    M->>O: reply
    O->>O: canary leak scan + full re-score
    O-->>U: clean reply
    O-->>U: OUTPUT_BLOCK → reply suppressed + alarm
    Note over D,O: every FLAG/BLOCK/OUTPUT_BLOCK is logged per user
```

## 🔐 Authentication & login-first flow

The whole app sits behind accounts: signed-out visitors who open `/`, `/chat-page` or `/dashboard` are redirected to `/login?next=…` (and returned where they headed after signing in), and the detector APIs (`/check`, `/batch-check`, `/chat`, `/api/dashboard`, `/api/report/*`, `/api/session/*`) return **401** without a session. Every detection is therefore attributed to a real account — no anonymous mode.

```mermaid
flowchart TB
    V["Visitor opens any page"] --> C{"valid session<br/>cookie?"}
    C -- "no (page)" --> R["303 → /login?next=path"]
    C -- "no (API)" --> E["401 Sign in required"]
    C -- "yes" --> APP["App renders / API responds"]
    R --> L["Login or Signup"]
    E --> L
    L --> V2["PBKDF2 verify / create user"]
    V2 --> CK["Set-Cookie pig_session<br/>HMAC v1.{user}.{exp}.{sig} · 30 days · httponly"]
    CK --> B["Redirect to next path or /dashboard"]
```

Per-user data model (Neon Postgres; SQLite fallback locally):

```mermaid
erDiagram
    USERS ||--o{ EVENTS : "owns (user_id)"
    USERS {
        text id PK
        text email
        text name
        text pw_hash
        real created_at
    }
    EVENTS {
        text id PK
        real ts
        text user_id FK
        text verdict
        real probability
        text attack_type
        text criticality
        text source
        bool canary
        text session_id
        text text
        text signals
    }
```

Schema details: `email` is unique per account, `pw_hash` stores a PBKDF2-SHA256 hash (200k iterations), `verdict` is `BLOCK / FLAG / OUTPUT_BLOCK` and `source` is `input / output`.

## 📡 API

| Endpoint | Description |
|---|---|
| `POST /api/auth/signup` | Create account (email + 8+ char password) → 201 + session cookie |
| `POST /api/auth/login` | Login → 200 + session cookie (401 on wrong password) |
| `POST /api/auth/logout` | Clear session |
| `GET /api/me` | Current user (or `null`) |
| `POST /check` 🔒 | `{"text": …}` → verdict, probability, signals, highlight spans |
| `POST /batch-check` 🔒 | Screen up to 100 texts at once |
| `POST /chat` 🔒 | Protected chat: input screening → LLM → output firewall; optional `session_id` |
| `GET /api/dashboard` 🔒 | Per-user stats, taxonomy, recent events (JSON) |
| `GET /api/report/{daily\|weekly\|monthly}` 🔒 | Per-user PDF security report |
| `GET /api/session/{id}` 🔒 | Per-session verdict history |
| `GET /providers` | Which LLM provider/model is active |
| `GET /` · `/chat-page` · `/dashboard` | UI pages (🔒 redirect to login when signed out) |

🔒 = requires session cookie (401 without).

## 🤖 Model-agnostic LLM providers

`/chat` auto-detects the configured provider from environment variables — all speak the OpenAI chat protocol:

| Provider | Env var | Default model |
|---|---|---|
| OpenAI / ChatGPT | `OPENAI_API_KEY` | gpt-4o-mini |
| Qwen (DashScope) | `QWEN_API_KEY` | qwen-plus |
| Groq (Llama / GPT-OSS) | `GROQ_API_KEY` | resolved dynamically |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| OpenRouter | `OPENROUTER_API_KEY` | openrouter/auto |
| Together AI | `TOGETHER_API_KEY` | Llama-3-8b |
| Any OpenAI-compatible endpoint | `CUSTOM_LLM_URL` + `CUSTOM_LLM_KEY` | `CUSTOM_LLM_MODEL` |

Groq note: model IDs rotate frequently, so the app resolves the best available chat model from the account's `/models` list at request time and falls back through a preference list — the demo never dead-ends mid-presentation. The deployed instance uses **Groq** and currently serves `openai/gpt-oss-120b`.

## 🧪 Training data

~17k labeled prompts from 3 public datasets (deepset prompt-injections, safeguard, jayavibhav) + 2.2k synthetic adversarial augmentations + a jailbreak-family augmentation pass that teaches the model itself to catch paraphrased red-team bypasses.

## 🧩 Chrome extension

`extension/` contains a Manifest V3 extension that checks any prompt typed into ChatGPT, Claude, Gemini, Qwen, DeepSeek, Copilot, Mistral, or Grok before you send it — floating button + auto-check on send, verdict banner with probability and signals. Load via `chrome://extensions` → Developer mode → Load unpacked.

## 💻 Local setup

```bash
python -m venv venv
venv/Scripts/pip install -r requirements.txt       # Windows; linux: venv/bin/pip
venv/Scripts/python scripts/unify_data.py           # build training data
venv/Scripts/python scripts/train_v3.py             # train + evaluate + save artifacts
venv/Scripts/python scripts/copy_models_to_api.py   # copy artifacts for Vercel
venv/Scripts/python -m uvicorn app:app --port 8000
```

`app.py` reads `.env` locally (provider key, optional `DATABASE_URL`, auto-generates `AUTH_SECRET` into `data/.auth_secret`); on Vercel use dashboard/CLI env vars.

## ☁️ Deployment (Vercel)

- `api/index.py` — serverless entry exposing the FastAPI app.
- `vercel.json` — Python 3.12 runtime, model artifacts bundled via `includeFiles` (committed in `models/`, ~4 MB).
- Environment variables:
  - `GROQ_API_KEY` (or any provider key) — powers the chat demo.
  - `DATABASE_URL` — Neon Postgres pooled connection string; persistent per-user store.
  - `AUTH_SECRET` — random hex; keeps sessions valid across cold starts.
- Deploy: `vercel --prod --yes`.

## ✅ Testing

| Script | What it does |
|---|---|
| `scripts/stress_test_v3.py [url]` | 29-case live accuracy report (signs in with a test account) — **29/29 local & production** |
| `scripts/test_auth.py [url]` | 24-check auth/scoping smoke test: signup, login, 401s, page gate, per-user isolation, per-user PDF |
| `scripts/redteam_multistep.py [url]` | 12 multi-step social-engineering scenarios (see [docs/MULTISTEP_REDTEAM.md](docs/MULTISTEP_REDTEAM.md)) |
| `scripts/take_screenshots.py [url]` | Regenerates the screenshots in `docs/screenshots/` via headless Chrome |

## 📁 Project layout

```
app.py                  FastAPI app: detector + protected chat + auth gate + provider layer
detector.py             Shared featurization + guardrails + highlight spans
auth.py                 Accounts (PBKDF2) + HMAC-signed session cookies + login-first helpers
attack_log.py           Event store (Neon Postgres / SQLite): taxonomy, criticality, session risk, per-user scope
report_generator.py     Periodic PDF security report (reportlab), per-account scope
static/                 Detector + chat + dashboard + login/signup UIs
extension/              Chrome extension for major AI chat sites
models/                 Trained v3 artifacts (committed, ~4 MB)
scripts/                train_v3, stress_test_v3, test_auth, redteam_multistep, take_screenshots, …
docs/                   MULTISTEP_REDTEAM.md + screenshots/
api/index.py + vercel.json  Vercel serverless deployment
data/                   Local store (gitignored): SQLite DB, .auth_secret
```
