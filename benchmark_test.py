import time
from app.ml.predict import get_classifier

sample_email = """From: security@paypal-verify.com
To: victim@company.com
Subject: URGENT: Your account has been suspended
Date: Mon, 12 May 2026 10:00:00 +0000

Dear Customer,
We detected unusual login activity. Please click the link below immediately to verify your credentials:
https://paypal-verify.com/account/login
Failure to respond within 24 hours will result in permanent account termination.
"""

clf = get_classifier()

# Benchmark 1: Feature Extraction + Calibrated 5-Class Inference
t0 = time.perf_counter()
pred = clf.predict_text(sample_email)
t_pred = (time.perf_counter() - t0) * 1000

# Benchmark 2: Exact Closed-Form SHAP Feature Attribution
t1 = time.perf_counter()
attrs, base_val = clf.explain(sample_email, class_name=pred.label, k=5)
t_shap = (time.perf_counter() - t1) * 1000

print("====================================================")
print("   LIVE BENCHMARK EXECUTING ON YOUR LOCAL CPU       ")
print("====================================================")
print(f"1. Scikit-Learn Feature Extraction + Inference : {t_pred:.3f} ms ({t_pred/1000:.5f} sec)")
print(f"2. Closed-Form SHAP Formula Calculation        : {t_shap:.3f} ms ({t_shap/1000:.5f} sec)")
print("----------------------------------------------------")
print(f"TOTAL ML + EXPLAINABILITY TIME                 : {t_pred + t_shap:.3f} ms ({((t_pred + t_shap)/1000):.5f} sec)")
print("====================================================")
print(f"Predicted Verdict: {pred.label.upper()} (Probability: {pred.probability*100:.1f}%)")
print("Top Explanatory SHAP Signals Extracted:")
for a in attrs:
    print(f"  • Feature: {a.feature_name:<25} | SHAP: {a.weight:+.4f} | Direction: {a.direction}")
