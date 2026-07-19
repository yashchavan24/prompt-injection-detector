import pandas as pd
import numpy as np
import re
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score

df = pd.read_csv("data/processed/combined.csv")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# ---- Heuristic feature extraction ----
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

    return [
        word_count,
        sentence_count,
        imperative_hits,
        imperative_density,
        has_roleplay_marker,
        has_override_marker,
        starts_with_imperative,
    ]

print("Extracting heuristic features for all examples...")
heuristic_feats = np.array([extract_features(t) for t in df["text"]])

print("Encoding embeddings...")
embeddings = embedder.encode(df["text"].tolist(), show_progress_bar=True)

# Combine embeddings + heuristic features
X_combined = np.hstack([embeddings, heuristic_feats])
df["_idx"] = range(len(df))

def run_cross_test(train_source, test_source):
    train_idx = df[df["source"] == train_source]["_idx"].values
    test_idx = df[df["source"] == test_source]["_idx"].values

    X_train, y_train = X_combined[train_idx], df.loc[train_idx, "label"].values
    X_test, y_test = X_combined[test_idx], df.loc[test_idx, "label"].values

    print(f"\nTraining on: {train_source} ({len(X_train)} examples)")
    print(f"Testing on:  {test_source} ({len(X_test)} examples, unseen)")

    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, preds, target_names=["benign", "injection"]))
    print("AUROC:", roc_auc_score(y_test, probs))

print("=" * 60)
print("IMPROVED TEST 1: Train on deepset -> Test on safeguard")
print("=" * 60)
run_cross_test("deepset", "safeguard")

print("\n" + "=" * 60)
print("IMPROVED TEST 2: Train on safeguard -> Test on deepset")
print("=" * 60)
run_cross_test("safeguard", "deepset")
