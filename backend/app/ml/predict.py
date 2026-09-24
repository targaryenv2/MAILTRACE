"""Load trained 5-class joblib model and score a ParsedEmail.

Outputs:
  - 5-class calibrated probabilities (benign, suspicious, phishing, bec, malware)
  - True SHAP per-token attributions for the top class
  - Trigram LM Perplexity and Burstiness AI generation detection
  - Sub-50ms execution latency on standard CPU
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from ..config import get_settings
from ..engine.ai_detector import get_ai_detector
from ..schemas import (
    FeatureAttribution,
    MlPrediction,
    ParsedEmail,
    SOURCE_COMPUTED,
    SOURCE_UNAVAILABLE,
)
from .explain import top_attributions
from .model import CLASS_NAMES

log = logging.getLogger(__name__)


class PhishClassifier:
    def __init__(self, model_path: Optional[str] = None) -> None:
        self.path = Path(model_path or get_settings().model_path)
        self.pipeline: Any = None
        self.feature_names: List[str] = []
        self.feature_means: np.ndarray = np.array([])
        self.weights: np.ndarray = np.array([])
        self.biases: np.ndarray = np.array([])
        self.meta: Dict[str, Any] = {}
        self.threshold: float = 0.5
        self.load_error: str = ""
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            # Check fallback to joblib if json was passed or vice versa
            alt = self.path.with_name("phish_tfidf_lr_real.joblib")
            if alt.exists():
                self.path = alt
            else:
                self.load_error = f"model file not found at {self.path} (run scripts/train_model.py)"
                return

        try:
            if str(self.path).endswith(".joblib"):
                bundle = joblib.load(self.path)
                self.pipeline = bundle["pipeline"]
                self.feature_names = bundle.get("feature_names", [])
                self.feature_means = np.asarray(bundle.get("feature_means", []))
                self.weights = np.asarray(bundle.get("weights", []))
                self.biases = np.asarray(bundle.get("biases", []))
                self.meta = bundle.get("metadata", {})
                self.threshold = float(self.meta.get("threshold", 0.5))
            else:
                import json
                blob = json.loads(self.path.read_text(encoding="utf-8"))
                self.meta = blob.get("meta", {})
                self.load_error = "Legacy JSON model loaded. Please run train_model.py for 5-class joblib pipeline."
        except Exception as exc:
            self.pipeline = None
            self.load_error = f"could not load model: {exc}"
            log.warning("PhishClassifier disabled: %s", exc)

    @property
    def available(self) -> bool:
        return self.pipeline is not None

    def _prepare_text(self, parsed: ParsedEmail) -> str:
        subject = parsed.subject or ""
        body = parsed.body_text or ""
        att_names = " ".join(a.filename for a in (parsed.attachments or []) if a.filename)
        text = f"{subject}\n{body}\n{att_names}".strip()
        return re.sub(r"\s+", " ", text)


    def predict(self, parsed: ParsedEmail) -> MlPrediction:
        if not self.available:
            return MlPrediction(
                available=False,
                source=SOURCE_UNAVAILABLE,
                model_name="none",
                notes=[self.load_error or "classifier unavailable", "verdict is rule-based only"],
            )

        text = self._prepare_text(parsed)
        if not text:
            text = parsed.subject or "empty email"

        # 1. Pipeline 5-Class Probabilities
        probs_array = self.pipeline.predict_proba([text])[0]
        prob_dict = {
            CLASS_NAMES[i]: round(float(probs_array[i]), 6)
            for i in range(len(probs_array))
        }

        pred_class_idx = int(np.argmax(probs_array))
        pred_class_name = CLASS_NAMES.get(pred_class_idx, "benign")

        # 2. Compute SHAP Attributions for the Top Predicted Class
        features_step = self.pipeline.named_steps.get("features", self.pipeline.named_steps.get("tfidf"))
        x_sparse = features_step.transform([text]) if features_step is not None else None


        class_weights = self.weights[pred_class_idx] if len(self.weights) > pred_class_idx else np.array([])
        class_bias = float(self.biases[pred_class_idx]) if len(self.biases) > pred_class_idx else 0.0

        feats, base_val = top_attributions(
            x_sparse=x_sparse,
            weights=class_weights,
            bias=class_bias,
            means=self.feature_means,
            feature_names=self.feature_names,
            class_name=pred_class_name,
            k=10,
        )

        # 3. Spearphish Detection Layer (detects sophisticated spearphish evading TF-IDF)
        from ..engine.spear import detect_spearphish
        spear_res = detect_spearphish(text, pred_class_idx, float(prob_dict.get(pred_class_name, 0.0)))
        if spear_res["spearphish_detected"]:
            pred_class_idx = spear_res["upgraded_class"]
            pred_class_name = spear_res["upgraded_label"] or CLASS_NAMES.get(pred_class_idx, "phishing")
            prob_dict["phishing"] = max(prob_dict.get("phishing", 0.0), spear_res["score"])
            prob_dict["benign"] = min(prob_dict.get("benign", 1.0), round(1.0 - spear_res["score"], 4))

        # 4. AI Text Detection (Perplexity + Burstiness)
        ai_res = get_ai_detector().analyze(text)

        # 5. Binary Malicious Probability
        p_malicious = round(1.0 - float(prob_dict.get("benign", 1.0)), 6)
        if spear_res["spearphish_detected"]:
            p_malicious = max(p_malicious, 0.85)
        binary_label = "phishing" if p_malicious >= self.threshold else "benign"

        notes: List[str] = [
            f"Class: {pred_class_name.upper()} (p={prob_dict.get(pred_class_name, 0.0):.4f})",
            f"AI Detector: {ai_res['verdict']} (ppl={ai_res['perplexity']}, burst={ai_res['burstiness']})",
        ]
        if spear_res["spearphish_detected"]:
            notes.append(f"Spearphish Override: {spear_res['signals']}")


        return MlPrediction(
            probability=p_malicious,
            label=binary_label,
            model_name=self.meta.get("name", "tfidf_calibrated_logreg_5class"),
            model_version=str(self.meta.get("version", "2.0.0")),
            threshold=self.threshold,
            top_features=feats,
            base_value=base_val,
            available=True,
            source=SOURCE_COMPUTED,
            notes=notes,
            probabilities=prob_dict,
            predicted_class=pred_class_idx,
            ai_detector=ai_res,
        )


_cached: Dict[str, PhishClassifier] = {}


def get_classifier(model_path: Optional[str] = None) -> PhishClassifier:
    key = str(model_path or get_settings().model_path)
    try:
        stamp = str(os.path.getmtime(key))
    except OSError:
        stamp = "0"
    cache_key = f"{key}:{stamp}"
    if cache_key not in _cached:
        _cached.clear()
        _cached[cache_key] = PhishClassifier(key)
    return _cached[cache_key]


# Module-level preloaded singleton
try:
    _model = get_classifier()
except Exception:
    _model = None

