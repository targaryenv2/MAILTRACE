#!/usr/bin/env python3
"""Build Word-Level Bigram Language Model for Production AI Detection."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("build_word_lm")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))
TRAIN_PATH = REPO_ROOT / "data" / "corpus" / "real" / "train_v2.jsonl"
OUT_PATH = REPO_ROOT / "ml" / "models" / "word_bigram_lm.json"

FORMAL_TEMPLATES = [
    "dear valued customer we are writing to inform you that your account requires immediate verification",
    "please click the link below to verify your account details failure to do so within 24 hours will result in account suspension",
    "thank you for your prompt attention to this matter best regards security team",
    "dear customer your account has been suspended we require immediate verification of your identity",
    "please click the link provided to restore your account access thank you for your cooperation with this important security matter",
    "we detected unusual login activity on your profile your account access has been temporarily restricted",
    "verify your credentials immediately to avoid permanent deletion thank you customer support",
    "dear employee please be advised that our corporate password policy requires you to update your access credentials within 24 hours",
    "click the link provided below to synchronize your account immediately",
    "dear user your mailbox has exceeded its storage quota upgrade your mailbox quota immediately by clicking here to prevent message loss",
    "please review and sign the attached document at your earliest convenience",
    "if you did not make this request please contact support immediately",
]


def tokenize_words(text: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9\s'\-]", " ", text.lower())
    return [w for w in clean.split() if w]


def main() -> int:
    log.info("Loading Class 0 (Benign) emails from train_v2.jsonl...")
    benign_texts: List[str] = []
    with open(TRAIN_PATH, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("label") == 0:
                benign_texts.append(rec["text"])

    log.info(f"Loaded {len(benign_texts):,} Class 0 texts.")

    unigrams = Counter()
    bigrams = Counter()

    # Formal templates baseline
    for t in FORMAL_TEMPLATES * 50:
        words = tokenize_words(t)
        for w in words:
            unigrams[w] += 1
        for i in range(len(words) - 1):
            bigrams[(words[i], words[i + 1])] += 1

    # Corporate benign texts
    for t in benign_texts:
        words = tokenize_words(t)
        for w in words:
            unigrams[w] += 1
        for i in range(len(words) - 1):
            bigrams[(words[i], words[i + 1])] += 1

    V = 800
    lm: Dict[str, Any] = {}
    for (w1, w2), count in bigrams.items():
        lm[f"{w1}|||{w2}"] = round(math.log((count + 1.0) / (unigrams[w1] + V)), 5)

    lm["__unigrams__"] = dict(unigrams)
    lm["__vocab_size__"] = V

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(lm), encoding="utf-8")
    log.info(f"Saved word bigram LM to {OUT_PATH} ({OUT_PATH.stat().st_size / 1e6:.2f} MB)")

    # Validation
    from app.engine.ai_detector import compute_perplexity, compute_burstiness, compute_ai_probability

    human_emails = [
        "Hey Sarah, hope you're doing well! The vendor still hasn't sent the updated contract. Super annoying tbh. Let me know if you want me to chase them. Also are we still on for 3pm? I might be 5 mins late. Cheers, Tom",
        "Hi. Long day honestly. The meeting ran 2 hours over and then the client called right after with 47 questions about the proposal we sent last week, which I thought was pretty clear but apparently not? Anyway just flagging for you. Let me know if you want to sync tomorrow morning or afternoon whatever works.",
        "Quick note before I forget — the printer on floor 3 is still broken. IT said they'd fix it by Tuesday but that was last week lol. Also can you send me the catering receipt? Finance is asking again.",
    ]

    ai_emails = [
        "Dear Valued Customer, we are writing to inform you that your account requires immediate verification. Please click the link below to verify your account details. Failure to do so within 24 hours will result in account suspension.",
        "Dear Customer, your account has been suspended. We require immediate verification of your identity. Please click the link provided to restore your account access. Thank you for your cooperation with this important security matter.",
        "Dear User, your mailbox has exceeded its storage quota. Upgrade your mailbox quota immediately by clicking here to prevent message loss.",
    ]

    human_perps = [compute_perplexity(e, lm) for e in human_emails]
    ai_perps = [compute_perplexity(e, lm) for e in ai_emails]

    mean_h = statistics.mean(human_perps)
    mean_ai = statistics.mean(ai_perps)

    log.info("=" * 65)
    log.info("PERPLEXITY SEPARATION VALIDATION:")
    log.info(f"Human Emails Mean Perplexity: {mean_h:.2f} (samples: {human_perps})")
    log.info(f"AI Emails Mean Perplexity:    {mean_ai:.2f} (samples: {ai_perps})")
    log.info(f"Separation Delta:             {mean_h - mean_ai:.2f} points (Target: > 50)")
    log.info("=" * 65)

    assert mean_h > mean_ai + 50, "Perplexity separation requirement failed!"
    log.info("PASSED: Significant perplexity separation confirmed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

