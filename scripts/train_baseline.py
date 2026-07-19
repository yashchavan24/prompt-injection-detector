import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

os.makedirs("models", exist_ok=True)

print("Loading data...")
df = pd.read_csv("data/processed/combined.csv")

print("Loading embedding model (this downloads ~90MB the first time)...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

print("Encoding all texts into embeddings... (this may take a minute or two on CPU)")
X = embedder.encode(df["text"].tolist(), show_progress_bar=True)
y = df["label"].values

# Standard same-dataset split (random, mixes both sources together)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining Logistic Regression classifier...")
clf = LogisticRegression(max_iter=1000)
clf.fit(X_train, y_train)

preds = clf.predict(X_test)
probs = clf.predict_proba(X_test)[:, 1]

print("\n=== SAME-DATASET EVALUATION (random split, sources mixed) ===")
print(classification_report(y_test, preds, target_names=["benign", "injection"]))
print("AUROC:", roc_auc_score(y_test, probs))

joblib.dump(clf, "models/baseline_logreg.pkl")
print("\nModel saved to models/baseline_logreg.pkl")
