import sys
import time
sys.path.insert(0, r"C:\Users\rama\Downloads\mailtrace\backend")

from app.schemas import ParsedEmail
from app.ml.predict import get_classifier

sample = ParsedEmail(
    subject="URGENT: Your payroll account requires mandatory verification",
    body_text="Dear Employee, please click the secure link below to update your direct deposit bank details immediately: https://payroll-portal-verify.top/login. Failure to verify within 24 hours will delay payment.",
    from_address="hr-payroll@payroll-portal-verify.top",
    to=["victim@corporate.com"]
)

clf = get_classifier()

# Warm up JIT / C runtime
_ = clf.predict(sample)

runs = 20
latencies = []
for _ in range(runs):
    t0 = time.perf_counter()
    pred = clf.predict(sample)
    latencies.append((time.perf_counter() - t0) * 1000)

avg_ms = sum(latencies) / len(latencies)

print("=" * 65)
print("     EMPIRICAL ML INFERENCE & SHAP BENCHMARK ON YOUR CPU      ")
print("=" * 65)
print(f"Total Test Inferences Run   : {runs} evaluations")
print(f"Average Total Execution Time: {avg_ms:.3f} milliseconds ({avg_ms/1000:.5f} seconds)")
print(f"Fastest Single Inference    : {min(latencies):.3f} milliseconds")
print(f"Slowest Single Inference    : {max(latencies):.3f} milliseconds")
print("-" * 65)
print(f"Predicted Class             : {pred.label.upper()} (Malicious Probability: {pred.probability*100:.2f}%)")
print(f"Class Breakdown Probabilities:")
for cls_name, prob in pred.probabilities.items():
    print(f"  • {cls_name:<12}: {prob*100:.2f}%")
print("-" * 65)
print(f"AI Detector Perplexity      : {pred.ai_detector.get('perplexity')} ({pred.ai_detector.get('verdict')})")
print(f"Exact SHAP Token Explanations Computed : {len(pred.top_features)} tokens")
print("Top Positive Risk SHAP Explanations:")
for attr in pred.top_features[:5]:
    print(f"  • Token: {attr.feature:<20} | Contribution: {attr.contribution:+.4f} | Direction: {attr.direction}")
print("=" * 65)
