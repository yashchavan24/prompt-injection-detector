from datasets import load_dataset
import os

os.makedirs("data", exist_ok=True)

print("Downloading deepset/prompt-injections...")
deepset = load_dataset("deepset/prompt-injections")
deepset.save_to_disk("data/deepset")

print("Downloading xTRam1/safe-guard-prompt-injection...")
safeguard = load_dataset("xTRam1/safe-guard-prompt-injection")
safeguard.save_to_disk("data/safeguard")

print("Done! Check the data/ folder.")
