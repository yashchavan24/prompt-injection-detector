from datasets import load_from_disk
import pandas as pd
import os

os.makedirs("data/processed", exist_ok=True)

# Load both datasets
deepset = load_from_disk("data/deepset")
safeguard = load_from_disk("data/safeguard")

def to_df(dataset_dict, source_name):
    dfs = []
    for split in dataset_dict.keys():
        df = dataset_dict[split].to_pandas()
        df["source"] = source_name
        df["original_split"] = split
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)

deepset_df = to_df(deepset, "deepset")
safeguard_df = to_df(safeguard, "safeguard")

# Combine everything into one master file (we will NOT shuffle sources together for training --
# this file is just a single reference. We split by source later.)
combined = pd.concat([deepset_df, safeguard_df], ignore_index=True)

print("Combined shape:", combined.shape)
print(combined["source"].value_counts())
print(combined["label"].value_counts())

combined.to_csv("data/processed/combined.csv", index=False)
print("\nSaved to data/processed/combined.csv")
