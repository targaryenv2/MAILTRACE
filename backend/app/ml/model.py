"""Production 5-Class Machine Learning Forensic Model.

Classes:
  0: Benign
  1: Suspicious
  2: Phishing
  3: BEC
  4: Malware

Architecture:
  - Scikit-Learn TfidfVectorizer(ngram_range=(1,3), max_features=50000, sublinear_tf=True, min_df=2)
  - CalibratedClassifierCV(LogisticRegression(multi_class="multinomial", class_weight="balanced"))
  - Serialized via joblib to ml/models/phish_tfidf_lr_real.joblib
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

log = logging.getLogger(__name__)

CLASS_NAMES = {
    0: "benign",
    1: "suspicious",
    2: "phishing",
    3: "bec",
    4: "malware"
}

CLASS_IDS = {v: k for k, v in CLASS_NAMES.items()}


def create_pipeline(max_features: int = 50000) -> Pipeline:
    """Build the production 5-class calibrated TF-IDF + Logistic Regression pipeline."""
    tfidf = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=max_features,
        sublinear_tf=True,
        analyzer="word",
        min_df=2,
    )
    base_clf = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
    )
    calibrated = CalibratedClassifierCV(estimator=base_clf, method="isotonic", cv=3)
    
    return Pipeline([
        ("tfidf", tfidf),
        ("clf", calibrated),
    ])
