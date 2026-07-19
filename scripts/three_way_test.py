import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

df = pd.read_csv("data/processed/combined_v2.csv")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

IMPERATIVE_WORDS = [
    "ignore", "disregard", "forget", "stop", "override", "bypass",
    "reveal", "pretend", "act as", "roleplay", "from now on",
    "new instructions", "system prompt", "you are now", "instead",
    "do not follow", "unrestricted", "jailbreak", "developer mode"
]

def extract_features(text):
    text_lower = str(text).lower()
    word_count = len(str(text).split())
    sentence_count = max(str(text).count(".") + str(text).count("!") + str(text).count("?"), 1)
    imperative_hits = sum(text_lower.count(w) for w in IMPERATIVE_WORDS)
    imperative_density = imperative_hits / max(word_count, 1)
    has_roleplay_marker = int(any(m in text_lower for m in
        ["pretend to be", "act as", "you are now", "roleplay as"]))
    has_override_marker = int(any(m in text_lower for m in
        ["ignore previous", "ignore all previous", "disregard the above",
         "forget previous", "new instructions"]))
    starts_with_imperative = int(str(text).strip().split(" ")[0].lower() in
        ["ignore", "forget", "stop", "disregard", "now", "pretend"])
    return [word_count, sentence_count, imperative_hits, imperative_density,
            has_roleplay_marker, has_override_marker, starts_with_imperative]

print("Extracting features for all examples (this will take a few minutes)...")
df["text"] = df["text"].astype(str)
heuristic_feats = np.array([extract_features(t) for t in df["text"]])
embeddings = embedder.encode(df["text"].tolist(), show_progress_bar=True)
X_all = np.hstack([embeddings, heuristic_feats])
df["_idx"] = range(len(df))

sources = ["deepset", "safeguard", "jayavibhav"]

def run_test(train_source, test_source):
    train_idx = df[df["source"] == train_source]["_idx"].values
    test_idx = df[df["source"] == test_source]["_idx"].values

    X_train, y_train = X_all[train_idx], df.loc[train_idx, "label"].values
    X_test, y_test = X_all[test_idx], df.loc[test_idx, "label"].values

    clf = RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    report = classification_report(y_test, preds, target_names=["benign","injection"], output_dict=True)
    auroc = roc_auc_score(y_test, probs)
    print(f"{train_source:12s} -> {test_source:12s}  AUROC={auroc:.3f}  Injection F1={report['injection']['f1-score']:.3f}  Recall={report['injection']['recall']:.3f}")

print("\n" + "="*70)
print("3-WAY CROSS-DATASET GENERALIZATION MATRIX")
print("="*70)
for train_s in sources:
    for test_s in sources:
        if train_s != test_s:
            run_test(train_s, test_s)
