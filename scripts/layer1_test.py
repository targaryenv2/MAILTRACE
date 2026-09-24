import json, statistics, os, random, sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
train_path = REPO_ROOT / "data" / "corpus" / "real" / "train.jsonl"
test_path = REPO_ROOT / "data" / "corpus" / "real" / "test.jsonl"

print("=" * 70)
print("LAYER 1: DATASET AUTHENTICITY")
print("=" * 70)

print("\n--- 1a. First 10 Raw Lines ---")
with open(train_path, encoding="utf-8") as f:
    lines = f.readlines()

for i, l in enumerate(lines[:10]):
    print(f"Line {i+1}: {l.strip()[:140]}...")

print("\n--- 1a. Last 10 Raw Lines ---")
for i, l in enumerate(lines[-10:]):
    print(f"Line {len(lines)-9+i}: {l.strip()[:140]}...")

texts = [json.loads(l)["text"] for l in lines]
lengths = [len(t) for t in texts]
print("\n--- 1a. Text Length Statistics ---")
print(f"Total texts: {len(texts)}")
print(f"Unique lengths: {len(set(lengths))}")
print(f"Mean length: {statistics.mean(lengths):.2f}")
print(f"Std dev: {statistics.stdev(lengths):.2f}")
print(f"Min: {min(lengths)}, Max: {max(lengths)}")

print("\n--- 1b. Label Distribution (train.jsonl) ---")
labels = [json.loads(l)["label"] for l in lines]
print("Counter(labels):", Counter(labels))

print("\n--- 1b. 3 Samples from Each Class ---")
by_class = {}
for l in lines:
    rec = json.loads(l)
    by_class.setdefault(rec["label"], []).append(rec)

random.seed(42)
for c in sorted(by_class.keys()):
    print(f"\n[CLASS {c} SAMPLES]")
    samples = random.sample(by_class[c], min(3, len(by_class[c])))
    for idx, s in enumerate(samples):
        src = s.get("source", "unknown")
        txt = s["text"].replace("\n", " ")
        print(f"  Sample {idx+1} [Source: {src} | Length: {len(s['text'])}]:")
        print(f"  {txt[:180]}...")

print("\n--- 1c. Source Distribution ---")
sources = [json.loads(l).get("source", "missing") for l in lines]
print(Counter(sources))

print("\n--- 1d. data/corpus Directory Listing ---")
for root, dirs, files in os.walk(REPO_ROOT / "data" / "corpus"):
    print(f"Directory: {root} ({len(dirs)} subdirs, {len(files)} files)")
    for f in files[:8]:
        sz = os.path.getsize(os.path.join(root, f))
        print(f"  - {f} ({sz:,} bytes)")
    if len(files) > 8:
        print(f"  ... and {len(files)-8} more files")

