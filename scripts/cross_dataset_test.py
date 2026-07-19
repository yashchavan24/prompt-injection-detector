import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score

df = pd.read_csv("data/processed/combined.csv")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

def run_cross_test(train_source, test_source):
    train_df = df[df["source"] == train_source]
    test_df = df[df["source"] == test_source]

    print(f"\nTraining on: {train_source} ({len(train_df)} examples)")
    print(f"Testing on:  {test_source} ({len(test_df)} examples, NEVER seen during training)")

    X_train = embedder.encode(train_df["text"].tolist(), show_progress_bar=False)
    X_test = embedder.encode(test_df["text"].tolist(), show_progress_bar=False)
    y_train = train_df["label"].values
    y_test = test_df["label"].values

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, preds, target_names=["benign", "injection"]))
    print("AUROC:", roc_auc_score(y_test, probs))

print("=" * 60)
print("CROSS-DATASET TEST 1: Train on deepset -> Test on safeguard")
print("=" * 60)
run_cross_test("deepset", "safeguard")

print("\n" + "=" * 60)
print("CROSS-DATASET TEST 2: Train on safeguard -> Test on deepset")
print("=" * 60)
run_cross_test("safeguard", "deepset")
