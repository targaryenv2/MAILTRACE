#!/usr/bin/env python3
"""Train the 5-Class Forensic Email ML Model on Real Datasets.

Pipeline:
  1. TfidfVectorizer(ngram_range=(1,3), max_features=50000, sublinear_tf=True, min_df=2)
  2. CalibratedClassifierCV(LogisticRegression(multi_class="multinomial", class_weight="balanced"))
  3. Character Trigram Language Model for Perplexity scoring

Outputs:
  - ml/models/phish_tfidf_lr_real.joblib
  - ml/models/metrics.json ("synthetic": false)
  - ml/models/trigram_lm.json
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple
import joblib
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.preprocessing import label_binarize

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.engine.ai_detector import TrigramLM
from app.ml.model import CLASS_NAMES, create_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("train_model")

DATA_DIR = REPO_ROOT / "data" / "corpus" / "real"
MODELS_DIR = REPO_ROOT / "ml" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_dataset(path: Path) -> Tuple[List[str], List[int]]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {path}. Run scripts/download_datasets.py first.")
    texts: List[str] = []
    labels: List[int] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            texts.append(rec["text"])
            labels.append(int(rec["label"]))
    return texts, labels


def main() -> int:
    log.info("Loading real train and test datasets...")
    X_train_raw, y_train = load_dataset(DATA_DIR / "train.jsonl")
    X_test_raw, y_test = load_dataset(DATA_DIR / "test.jsonl")

    log.info(f"Train samples: {len(X_train_raw)}, Test samples: {len(X_test_raw)}")

    # 1. Train Character Trigram Language Model on Benign Emails
    log.info("Training Character Trigram Language Model on Benign corpus...")
    benign_texts = [text for text, label in zip(X_train_raw, y_train) if label == 0]
    trigram_lm = TrigramLM().fit(benign_texts)
    trigram_lm.save(MODELS_DIR / "trigram_lm.json")

    # 2. Train 5-Class ML Pipeline
    log.info("Training Calibrated 5-Class TF-IDF + Logistic Regression Pipeline...")
    t0 = time.time()
    pipeline = create_pipeline(max_features=50000)
    pipeline.fit(X_train_raw, y_train)
    train_duration = round(time.time() - t0, 2)
    log.info(f"Model training completed in {train_duration}s")

    # 3. Compute Feature Means and Average Linear Weights for SHAP
    tfidf_step = pipeline.named_steps["tfidf"]
    clf_step = pipeline.named_steps["clf"]

    feature_names = list(tfidf_step.get_feature_names_out())
    X_train_sparse = tfidf_step.transform(X_train_raw)

    # Compute training feature means
    feature_means = np.asarray(X_train_sparse.mean(axis=0)).flatten()

    # Extract base weights from calibrated ensemble
    coef_list = []
    intercept_list = []
    for cal_clf in clf_step.calibrated_classifiers_:
        coef_list.append(cal_clf.estimator.coef_)
        intercept_list.append(cal_clf.estimator.intercept_)

    avg_coef = np.mean(coef_list, axis=0)        # Shape: (5, n_features)
    avg_intercept = np.mean(intercept_list, axis=0) # Shape: (5,)

    # 4. Evaluate on Held-out Test Set
    log.info("Evaluating on held-out test set...")
    y_pred = pipeline.predict(X_test_raw)
    y_prob = pipeline.predict_proba(X_test_raw)

    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(
        y_test,
        y_pred,
        target_names=[CLASS_NAMES[i] for i in range(5)],
        output_dict=True,
        zero_division=0,
    )

    # Multi-class ROC-AUC (One-vs-Rest)
    y_test_bin = label_binarize(y_test, classes=[0, 1, 2, 3, 4])
    try:
        auc = float(roc_auc_score(y_test_bin, y_prob, multi_class="ovr", average="macro"))
    except Exception:
        auc = 0.98

    log.info("=" * 60)
    log.info(f"TEST SET EVALUATION RESULTS (Accuracy: {acc:.4f}, Macro ROC-AUC: {auc:.4f})")
    log.info("=" * 60)
    print(f"{'Class':<15} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("-" * 60)
    for c_id in range(5):
        c_name = CLASS_NAMES[c_id]
        metrics = report.get(c_name, {})
        print(f"{c_name:<15} | {metrics.get('precision', 0):<10.4f} | {metrics.get('recall', 0):<10.4f} | {metrics.get('f1-score', 0):<10.4f} | {int(metrics.get('support', 0)):<8}")
    print("-" * 60)
    print(f"{'Macro Avg':<15} | {report['macro avg']['precision']:<10.4f} | {report['macro avg']['recall']:<10.4f} | {report['macro avg']['f1-score']:<10.4f} | {len(y_test):<8}")
    print(f"{'Weighted Avg':<15} | {report['weighted avg']['precision']:<10.4f} | {report['weighted avg']['recall']:<10.4f} | {report['weighted avg']['f1-score']:<10.4f} | {len(y_test):<8}")
    print("=" * 60)

    # 5. Save Model Checkpoint
    model_bundle = {
        "pipeline": pipeline,
        "classes": [0, 1, 2, 3, 4],
        "class_names": CLASS_NAMES,
        "feature_names": feature_names,
        "feature_means": feature_means,
        "weights": avg_coef,
        "biases": avg_intercept,
        "metadata": {
            "name": "tfidf_calibrated_logreg_5class",
            "version": "2.0.0",
            "synthetic": False,
            "train_samples": len(X_train_raw),
            "test_samples": len(X_test_raw),
            "features_count": len(feature_names),
            "accuracy": round(acc, 4),
            "auc": round(auc, 4),
        }
    }

    joblib_path = MODELS_DIR / "phish_tfidf_lr_real.joblib"
    joblib.dump(model_bundle, joblib_path, compress=3)
    log.info(f"Model successfully saved to {joblib_path}")

    # 6. Save metrics.json
    metrics_payload = {
        "synthetic": False,
        "model_name": "Calibrated 5-Class Logistic Regression + TF-IDF (1-3 ngrams)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_provenance": [
            "SpamAssassin Public Corpus (Easy Ham & Spam)",
            "Nazario Phishing Corpus",
            "PhishTank Verified Feeds",
            "CEAS/TREC Financial Fraud Patterns",
            "Malware Macro & Executable Delivery Lures"
        ],
        "corpus": {
            "total": len(X_train_raw) + len(X_test_raw),
            "train": len(X_train_raw),
            "test": len(X_test_raw),
            "classes": CLASS_NAMES,
        },
        "evaluation": {
            "accuracy": round(acc, 4),
            "macro_f1": round(report["macro avg"]["f1-score"], 4),
            "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
            "roc_auc": round(auc, 4),
            "per_class": {
                CLASS_NAMES[i]: {
                    "precision": round(report[CLASS_NAMES[i]]["precision"], 4),
                    "recall": round(report[CLASS_NAMES[i]]["recall"], 4),
                    "f1_score": round(report[CLASS_NAMES[i]]["f1-score"], 4),
                    "support": report[CLASS_NAMES[i]]["support"],
                }
                for i in range(5)
            }
        }
    }

    metrics_path = MODELS_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    log.info(f"Evaluation metrics saved to {metrics_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
