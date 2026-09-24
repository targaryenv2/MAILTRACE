import json, joblib, random, sys
from pathlib import Path
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent

print("=" * 70)
print("LAYER 2: MODEL AUTHENTICITY")
print("=" * 70)

print("\n--- 2a. Raw metrics.json ---")
metrics_path = REPO_ROOT / "ml" / "models" / "metrics.json"
if metrics_path.exists():
    print(metrics_path.read_text(encoding="utf-8"))
else:
    print("metrics.json NOT FOUND!")

print("\n--- 2b. Inspecting phish_tfidf_lr_real.joblib ---")
model_bundle = joblib.load(REPO_ROOT / "ml" / "models" / "phish_tfidf_lr_real.joblib")
print("Bundle Type:", type(model_bundle))
print("Bundle Keys:", list(model_bundle.keys()) if isinstance(model_bundle, dict) else "Not a dict")

pipeline = model_bundle["pipeline"] if isinstance(model_bundle, dict) else model_bundle
print("Pipeline Type:", type(pipeline))
print("Named Steps:", pipeline.named_steps.keys() if hasattr(pipeline, "named_steps") else "No named_steps")

vec = pipeline.named_steps.get("tfidf") or pipeline.named_steps.get("tfidfvectorizer") or pipeline[0]
vocab = vec.vocabulary_
print(f"Vocabulary size: {len(vocab)}")

random.seed(42)
sample_terms = random.sample(list(vocab.keys()), 20)
print("20 Random Vocab Sample Terms:\n", sample_terms)

print("\n--- 2c. Probing Model with Handcrafted Inputs ---")
test_cases = [
    ("Your account has been suspended please verify immediately", 
     "expected: Phishing/Suspicious (class 2 or 1)"),
    ("Please wire $50,000 to the new vendor account by EOD per CEO request", 
     "expected: BEC (class 3)"),
    ("Hi team, attached is the Q3 report for your review", 
     "expected: Benign (class 0)"),
    ("Open the attached macro-enabled spreadsheet to view your invoice", 
     "expected: Malware (class 4)"),
    ("Congratulations you have won a prize click here to claim", 
     "expected: Suspicious/Phishing (class 1 or 2)"),
]

for text, expected in test_cases:
    probs = pipeline.predict_proba([text])[0]
    pred = pipeline.predict([text])[0]
    print(f"\nText: '{text}'")
    print(f"Expected: {expected}")
    print(f"Predicted class: {pred} ({model_bundle['class_names'][pred]})")
    print(f"Probabilities B/S/P/BEC/M: {[round(float(p), 4) for p in probs]}")

print("\n--- 2d. Train/Test Data Leakage & Overlap Check ---")
train_texts = set(json.loads(l)["text"] for l in open(REPO_ROOT / "data" / "corpus" / "real" / "train.jsonl", encoding="utf-8"))
test_texts = [json.loads(l)["text"] for l in open(REPO_ROOT / "data" / "corpus" / "real" / "test.jsonl", encoding="utf-8")]

overlap = sum(1 for t in test_texts if t in train_texts)
print(f"Train/test exact overlap: {overlap} out of {len(test_texts)} test samples")
print(f"Train unique count: {len(train_texts)}, Test count: {len(test_texts)}")

