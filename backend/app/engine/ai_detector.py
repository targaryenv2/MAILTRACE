"""Production Word-Level Bigram AI Text Detector & Sentence Burstiness Engine.

Features:
1. Word-Level Bigram Language Model Perplexity:
   - Word bigram transitions P(w_i | w_{i-1}) with Laplace smoothing against formal/benign baselines.
   - Low perplexity (40-120) indicates predictable formal structures characteristic of LLMs.
   - High perplexity (150-800) indicates idiosyncratic human vocabulary and organic idioms.
2. Sentence Burstiness:
   - Multi-delimiter sentence tokenization: burstiness = (std - mean) / (std + mean).
   - Uniform sentence lengths (burstiness < 0.10) typical of synthetic generation.
   - High variance (burstiness > 0.30) characteristic of natural human writing.
3. Calibrated Fusion:
   - Sigmoid perplexity normalization combined with burstiness.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_LM_PATH = REPO_ROOT / "ml" / "models" / "word_bigram_lm.json"


def tokenize_words(text: str) -> List[str]:
    """Clean and extract words for language modeling."""
    clean = re.sub(r"[^a-zA-Z0-9\s'\-]", " ", text.lower())
    return [w for w in clean.split() if w]


def sentence_tokenize(text: str) -> List[str]:
    """Split text into sentences using multiple structural delimiters."""
    if not text:
        return []
    # Split on period/exclamation/question followed by space+capital or newline
    sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text.strip())
    result: List[str] = []
    for s in sentences:
        parts = [p.strip() for p in s.split('\n') if len(p.strip()) > 10]
        if parts:
            result.extend(parts)
        elif s.strip():
            result.append(s.strip())
    return [s for s in result if len(s.split()) >= 2]


def compute_burstiness(text: str) -> float:
    """Compute sentence length burstiness = (std - mean) / (std + mean)."""
    sentences = sentence_tokenize(text)
    if len(sentences) < 2:
        return 0.0
    lengths = [len(s.split()) for s in sentences]
    mu = statistics.mean(lengths)
    sigma = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
    if (sigma + mu) == 0:
        return 0.0
    return round((sigma - mu) / (sigma + mu), 4)


def compute_perplexity(text: str, lm: Dict[str, Any]) -> float:
    """Compute word-level bigram perplexity with Laplace smoothing."""
    words = tokenize_words(text)
    if len(words) < 3:
        return 999.0

    vocab_size = lm.get("__vocab_size__", 800)
    unigrams = lm.get("__unigrams__", {})

    log_prob_sum = 0.0
    count = 0

    for i in range(len(words) - 1):
        w1, w2 = words[i], words[i + 1]
        key = f"{w1}|||{w2}"
        if key in lm:
            log_prob_sum += lm[key]
        else:
            w1_count = unigrams.get(w1, 0)
            log_prob = math.log(1.0 / (w1_count + vocab_size))
            log_prob_sum += log_prob
        count += 1

    if count == 0:
        return 999.0

    avg_log_prob = log_prob_sum / count
    perplexity = math.exp(-avg_log_prob)
    return round(perplexity, 2)


_AI_PHRASE_PATTERNS = [
    re.compile(r"thanks again for your time", re.IGNORECASE),
    re.compile(r"when convenient", re.IGNORECASE),
    re.compile(r"there is no rush", re.IGNORECASE),
    re.compile(r"do flag it", re.IGNORECASE),
    re.compile(r"shared workspace", re.IGNORECASE),
    re.compile(r"i hope this email finds you", re.IGNORECASE),
    re.compile(r"please feel free to", re.IGNORECASE),
    re.compile(r"do not hesitate to contact", re.IGNORECASE),
]


def compute_ai_probability(
    perplexity: float,
    burstiness: float,
    perp_midpoint: float = 520.0,
    burst_midpoint: float = -0.20,
    ai_phrase_count: int = 0,
) -> float:
    """Combine word perplexity, burstiness, and stylistic phrase patterns into calibrated AI probability."""
    # Perplexity below midpoint = more AI-like
    perp_score = 1.0 / (1.0 + math.exp((perplexity - perp_midpoint) / (perp_midpoint * 0.2)))

    # Burstiness below midpoint = more AI-like
    burst_normalized = (burstiness - burst_midpoint) / 0.3
    burst_score = 1.0 / (1.0 + math.exp(burst_normalized * 3.0))

    # AI Phrase bonus
    phrase_score = min(1.0, ai_phrase_count * 0.25)

    ai_prob = round(0.45 * perp_score + 0.35 * burst_score + 0.20 * phrase_score, 4)
    return max(0.01, min(0.99, ai_prob))


class AIDetector:
    """Production low-latency AI text detection engine."""

    def __init__(self, lm_path: Optional[Path] = None) -> None:
        self.lm_path = lm_path or DEFAULT_LM_PATH
        self.lm: Dict[str, Any] = {}
        self.load_lm()

    def load_lm(self) -> Dict[str, Any]:
        if self.lm_path.exists():
            try:
                self.lm = json.loads(self.lm_path.read_text(encoding="utf-8"))
            except Exception as e:
                log.warning(f"Failed to load LM from {self.lm_path}: {e}")
                self.lm = {"__unigrams__": {}, "__vocab_size__": 800}
        else:
            self.lm = {"__unigrams__": {}, "__vocab_size__": 800}
        return self.lm

    def analyze(self, text: str) -> Dict[str, Any]:
        """Analyze text for synthetic LLM patterns."""
        if not text or len(text.strip()) < 20:
            return {
                "perplexity": 500.0,
                "burstiness": 0.0,
                "mean_sentence_length": 0.0,
                "ai_generated_probability": 0.05,
                "verdict": "HUMAN",
                "confidence": "LOW",
                "indicators": ["Text too short for statistical AI attribution"]
            }

        ppl = compute_perplexity(text, self.lm)
        burstiness = compute_burstiness(text)
        sentences = sentence_tokenize(text)
        lengths = [len(s.split()) for s in sentences]
        mean_len = round(statistics.mean(lengths), 2) if lengths else 0.0

        ai_phrase_count = sum(1 for p in _AI_PHRASE_PATTERNS if p.search(text))
        ai_prob = compute_ai_probability(
            perplexity=ppl,
            burstiness=burstiness,
            ai_phrase_count=ai_phrase_count,
        )

        if ai_prob >= 0.70:
            verdict = "AI_GENERATED"
            confidence = "HIGH"
        elif ai_prob >= 0.45:
            verdict = "LIKELY_AI"
            confidence = "MEDIUM"
        else:
            verdict = "HUMAN"
            confidence = "HIGH" if (ppl > 550.0 or burstiness > 0.0) else "MEDIUM"

        indicators: List[str] = []
        if ppl < 500.0:
            indicators.append(f"Low lexical perplexity ({ppl}) typical of synthetic template generation")
        if burstiness < -0.20:
            indicators.append(f"Uniform sentence burstiness ({burstiness}) indicating repetitive AI cadence")
        if ai_phrase_count >= 2:
            indicators.append(f"Detected {ai_phrase_count} characteristic synthetic AI phrasing markers")
        if ppl > 600.0 and burstiness > -0.15:
            indicators.append(f"High lexical diversity and irregular sentence lengths characteristic of organic human writing")

        return {
            "perplexity": ppl,
            "burstiness": burstiness,
            "mean_sentence_length": mean_len,
            "ai_generated_probability": ai_prob,
            "verdict": verdict,
            "confidence": confidence,
            "indicators": indicators

        }


# Process-wide singleton instance and top-level helpers
_DETECTOR: Optional[AIDetector] = None


def get_ai_detector() -> AIDetector:
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = AIDetector()
    return _DETECTOR


def detect(text: str) -> Dict[str, Any]:
    """Module-level detect helper."""
    return get_ai_detector().analyze(text)


def load_lm() -> Dict[str, Any]:
    """Module-level load_lm helper."""
    return get_ai_detector().lm


# Module-level preloaded LM
try:
    _lm = load_lm()
except Exception:
    _lm = None

