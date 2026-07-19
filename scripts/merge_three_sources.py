from datasets import load_from_disk
import pandas as pd
import os

os.makedirs("data/processed", exist_ok=True)

def to_df(dataset_dict, source_name):
    dfs = []
    for split in dataset_dict.keys():
        df = dataset_dict[split].to_pandas()
        df["source"] = source_name
        df["original_split"] = split
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)

print("Loading deepset...")
deepset_df = to_df(load_from_disk("data/deepset"), "deepset")

print("Loading safeguard...")
safeguard_df = to_df(load_from_disk("data/safeguard"), "safeguard")

print("Loading jayavibhav (sampling to keep it manageable)...")
jaya = load_from_disk("data/jayavibhav")
jaya_df = to_df(jaya, "jayavibhav")

# Balanced sample of ~3000 per class (6000 total) so encoding doesn't take forever
jaya_benign = jaya_df[jaya_df.label == 0].sample(n=min(3000, (jaya_df.label==0).sum()), random_state=42)
jaya_inject = jaya_df[jaya_df.label == 1].sample(n=min(3000, (jaya_df.label==1).sum()), random_state=42)
jaya_sampled = pd.concat([jaya_benign, jaya_inject], ignore_index=True)

print(f"deepset: {len(deepset_df)}, safeguard: {len(safeguard_df)}, jayavibhav (sampled): {len(jaya_sampled)}")

combined = pd.concat([deepset_df, safeguard_df, jaya_sampled], ignore_index=True)
print("\nTotal combined:", len(combined))
print(combined["source"].value_counts())
print(combined["label"].value_counts())

combined.to_csv("data/processed/combined_v2.csv", index=False)
print("\nSaved to data/processed/combined_v2.csv")
