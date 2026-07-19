import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

os.makedirs("models", exist_ok=True)

df = pd.read_csv("data/processed/combined_v2.csv")
df["text"] = df["text"].astype(str)

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

print("Fitting TF-IDF vectorizer (max 3000 features, lightweight)...")
vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1,2), min_df=2)
X_tfidf = vectorizer.fit_transform(df["text"]).toarray()

print("Extracting heuristic features...")
heuristic_feats = np.array([extract_features(t) for t in df["text"]])

X = np.hstack([X_tfidf, heuristic_feats])
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Training Logistic Regression (lightweight, no torch needed)...")
clf = LogisticRegression(max_iter=1000, class_weight="balanced")
clf.fit(X_train, y_train)

preds = clf.predict(X_test)
probs = clf.predict_proba(X_test)[:, 1]
print(classification_report(y_test, preds, target_names=["benign","injection"]))
print("AUROC:", roc_auc_score(y_test, probs))

# Retrain on ALL data for final deployed model
clf_final = LogisticRegression(max_iter=1000, class_weight="balanced")
clf_final.fit(X, y)
joblib.dump(clf_final, "models/lite_model.pkl")
joblib.dump(vectorizer, "models/lite_vectorizer.pkl")
print("\nSaved lightweight model and vectorizer to models/")
