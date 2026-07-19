import pandas as pd
import numpy as np
import re
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

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

print("Extracting heuristic features...")
heuristic_feats = np.array([extract_features(t) for t in df["text"]])

print("Encoding embeddings...")
embeddings = embedder.encode(df["text"].tolist(), show_progress_bar=True)

df["_idx"] = range(len(df))

def run_cross_test(train_source, test_source, feature_mode, balanced):
    train_idx = df[df["source"] == train_source]["_idx"].values
    test_idx = df[df["source"] == test_source]["_idx"].values

    if feature_mode == "embeddings_only":
        X = embeddings
    elif feature_mode == "heuristics_only":
        X = heuristic_feats
    else:  # combined
        X = np.hstack([embeddings, heuristic_feats])

    X_train_raw, y_train = X[train_idx], df.loc[train_idx, "label"].values
    X_test_raw, y_test = X[test_idx], df.loc[test_idx, "label"].values

    # Scale features -- fit scaler on TRAIN only, apply to both
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    clf = LogisticRegression(max_iter=1000, class_weight="balanced" if balanced else None)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    f1_injection = classification_report(y_test, preds, target_names=["benign","injection"], output_dict=True)["injection"]["f1-score"]
    recall_injection = classification_report(y_test, preds, target_names=["benign","injection"], output_dict=True)["injection"]["recall"]
    auroc = roc_auc_score(y_test, probs)
    print(f"  [{feature_mode:18s} | balanced={str(balanced):5s}] AUROC={auroc:.3f}  Injection F1={f1_injection:.3f}  Injection Recall={recall_injection:.3f}")
    return auroc

configs = ["embeddings_only", "heuristics_only", "combined"]

for direction, (train_s, test_s) in [("deepset -> safeguard", ("deepset","safeguard")),
                                       ("safeguard -> deepset", ("safeguard","deepset"))]:
    print(f"\n{'='*70}\nDIRECTION: {direction}\n{'='*70}")
    for feat_mode in configs:
        for bal in [False, True]:
            run_cross_test(train_s, test_s, feat_mode, bal)
