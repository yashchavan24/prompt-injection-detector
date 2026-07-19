import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

os.makedirs("models", exist_ok=True)

df = pd.read_csv("data/processed/combined.csv")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

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

print("Extracting features...")
heuristic_feats = np.array([extract_features(t) for t in df["text"]])
embeddings = embedder.encode(df["text"].tolist(), show_progress_bar=True)
X = np.hstack([embeddings, heuristic_feats])
y = df["label"].values

print("Training final Random Forest on ALL data...")
clf = RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
clf.fit(X, y)

joblib.dump(clf, "models/final_rf_model.pkl")
print("Saved final model to models/final_rf_model.pkl")
