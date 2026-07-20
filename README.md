# Prompt Injection Detector

A machine learning-based system for detecting prompt injection attacks in LLM-integrated applications, built as a final year B.Tech Cyber Security project.

**Live demo:** https://prompt-injection-detector-g0v0.onrender.com
(Free tier hosting -- first request may take up to 50 seconds if the instance has spun down from inactivity.)

## Overview

Large Language Models integrated into real applications (chatbots, coding assistants, browser agents) are vulnerable to prompt injection -- attacks where malicious input overrides the model's intended instructions. This project builds a lightweight middleware classifier that screens prompts before they reach an LLM, blocking or flagging likely injection attempts in real time.

Unlike most published detectors, which report near-perfect accuracy on same-dataset evaluation, this project explicitly measures performance under **cross-dataset generalization** -- training on one set of attack patterns and testing on genuinely unseen ones -- to reflect real deployment conditions rather than dataset artifacts.

## Key results

| Evaluation | Result |
|---|---|
| Same-dataset (random split, 2 sources mixed) | 99.4% AUROC |
| Cross-dataset generalization (2 sources) | ~0.72 AUROC average |
| 3-way cross-dataset generalization (3 sources) | 0.71-0.97 AUROC (highly source-dependent) |
| Adversarial stress test -- obvious attacks | 100% (13/13) |
| Adversarial stress test -- novel/paraphrased attacks (2-source model) | 62.5% (5/8) |
| Adversarial stress test -- novel/paraphrased attacks (3-source model) | 87.5% (7/8) |

Full methodology, literature review, and analysis are in the project report.

## Architecture

- **Detection model (research/local):** Sentence embeddings (all-MiniLM-L6-v2) + hand-crafted heuristic features (imperative-word density, roleplay/override markers) -> Random Forest classifier
- **Detection model (deployed/lightweight):** TF-IDF features + heuristic features -> Logistic Regression classifier (chosen for deployment to fit within free-tier memory limits)
- **Backend:** FastAPI, with `/check` (score any text) and `/chat` (protected chatbot demo wired to Llama 3.1 via Groq's API) endpoints
- **Frontend:** Vanilla HTML/CSS/JS, dark-themed UI showing verdict, probability, and triggered signals
- **Browser extension:** Chrome extension (Manifest V3) with a popup checker and a floating "Check for injection" button injected into ChatGPT/Copilot pages

## Datasets used

- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
- [xTRam1/safe-guard-prompt-injection](https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection)
- [jayavibhav/prompt-injection](https://huggingface.co/datasets/jayavibhav/prompt-injection) (sampled subset)

## Repo structure
app.py Full local app (embeddings-based model, requires torch)
app_deploy.py Lightweight deployed app (TF-IDF-based model, no torch)
requirements.txt Dependencies for the deployed (lite) version
scripts/ Data pipeline, training, and evaluation scripts
models/ Trained model artifacts (.pkl)
static/ Web UI (detector page + protected chatbot demo)
extension/ Chrome extension (Manifest V3)

## Running locally

python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app_deploy:app --reload

Then open http://127.0.0.1:8000

To use the full embeddings-based model instead, install `torch` and `sentence-transformers` additionally and run `uvicorn app:app --reload`.

## Limitations

- The detector is specifically trained to catch prompt injection / instruction-override patterns -- it is not a general content moderation filter (a directly harmful request that isn't an injection attempt may pass through, as demonstrated in testing).
- Cross-dataset generalization remains an open challenge; performance varies significantly depending on which dataset combination is used for training vs. testing.
- The lightweight deployed model (TF-IDF-based) has not been evaluated on the same cross-dataset/adversarial benchmarks as the full embeddings-based model.
