from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import numpy as np
import joblib
import os
import requests
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

app = FastAPI(title="Prompt Injection Detector (Lite)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Loading lightweight model and vectorizer...")
clf = joblib.load("models/lite_model.pkl")
vectorizer = joblib.load("models/lite_vectorizer.pkl")
print("Ready.")

IMPERATIVE_WORDS = [
    "ignore", "disregard", "forget", "stop", "override", "bypass",
    "reveal", "pretend", "act as", "roleplay", "from now on",
    "new instructions", "system prompt", "you are now", "instead",
    "do not follow", "unrestricted", "jailbreak", "developer mode"
]

def extract_features(text):
    text_lower = text.lower()
    word_count = len(text.split())
    sentence_count = max(text.count(".") + text.count("!") + text.count("?"), 1)
    imperative_hits = sum(text_lower.count(w) for w in IMPERATIVE_WORDS)
    imperative_density = imperative_hits / max(word_count, 1)
    has_roleplay_marker = int(any(m in text_lower for m in
        ["pretend to be", "act as", "you are now", "roleplay as"]))
    has_override_marker = int(any(m in text_lower for m in
        ["ignore previous", "ignore all previous", "disregard the above",
         "forget previous", "new instructions"]))
    starts_with_imperative = int(text.strip().split(" ")[0].lower() in
        ["ignore", "forget", "stop", "disregard", "now", "pretend"])
    return [word_count, sentence_count, imperative_hits, imperative_density,
            has_roleplay_marker, has_override_marker, starts_with_imperative]

def score_text(text):
    tfidf_vec = vectorizer.transform([text]).toarray()
    heuristics = np.array([extract_features(text)])
    X = np.hstack([tfidf_vec, heuristics])
    return clf.predict_proba(X)[0][1]

class PromptRequest(BaseModel):
    text: str

@app.post("/check")
def check_prompt(req: PromptRequest):
    prob = score_text(req.text)
    verdict = "BLOCK" if prob > 0.7 else "FLAG" if prob > 0.4 else "ALLOW"
    feats = extract_features(req.text)
    return {
        "text": req.text,
        "injection_probability": round(float(prob), 3),
        "verdict": verdict,
        "signals": {
            "imperative_word_hits": feats[2],
            "has_roleplay_marker": bool(feats[4]),
            "has_override_marker": bool(feats[5])
        }
    }

class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
def protected_chat(req: ChatRequest):
    prob = score_text(req.message)
    if prob > 0.7:
        return {
            "blocked": True,
            "injection_probability": round(float(prob), 3),
            "reply": "This message was blocked before reaching the AI model because it looked like a prompt injection attempt."
        }

    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
        json={
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": req.message}
            ]
        }
    )
    data = response.json()
    try:
        reply_text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        reply_text = "Error calling the language model. Check your API key."

    return {
        "blocked": False,
        "injection_probability": round(float(prob), 3),
        "reply": reply_text
    }

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse("static/index.html")
