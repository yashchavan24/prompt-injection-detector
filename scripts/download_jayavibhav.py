from datasets import load_dataset
import os

os.makedirs("data", exist_ok=True)

print("Downloading jayavibhav/prompt-injection...")
ds = load_dataset("jayavibhav/prompt-injection")
print(ds)
ds.save_to_disk("data/jayavibhav")
print("Done.")
