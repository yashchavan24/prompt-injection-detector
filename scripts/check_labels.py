from datasets import load_from_disk
from collections import Counter

for name in ["deepset", "safeguard"]:
    print("=" * 50)
    print(name.upper())
    print("=" * 50)
    ds = load_from_disk(f"data/{name}")
    for split in ds.keys():
        labels = ds[split]["label"]
        print(f"{split} label counts:", Counter(labels))

    # show a couple of actual injection examples (label == 1)
    train = ds["train"]
    injection_examples = [ex for ex in train if ex["label"] == 1][:3]
    print("\nSample INJECTION (label=1) examples:")
    for ex in injection_examples:
        print("-", ex["text"][:200])
    print()
