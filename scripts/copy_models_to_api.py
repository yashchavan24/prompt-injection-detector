"""Copy model artifacts into api/models so Vercel bundles them with the lambda."""
import os
import shutil

os.makedirs("api/models", exist_ok=True)
for f in ("v3_word_vec.pkl", "v3_char_vec.pkl", "v3_scaler.pkl",
          "v3_model.pkl", "v3_meta.json"):
    src = os.path.join("models", f)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join("api", "models", f))
        print("copied", f)
    else:
        print("WARNING missing", src)
