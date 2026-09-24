import json, sys
from pathlib import Path
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ingestion.parser import parse_eml
from app.ml.predict import get_classifier
from app.geoip.resolver import resolve_ip
from app.detection.engine import check_language
from app.pipeline import build_case
from app.agent.loop import investigate

print("=" * 70)
print("LAYER 6: END-TO-END PIPELINE INTEGRITY")
print("=" * 70)

print("\n--- 6a. Deep Inspection of 02-bec-wire-transfer.eml ---")
eml_02_path = REPO_ROOT / "data" / "demo" / "02-bec-wire-transfer.eml"
raw_02 = eml_02_path.read_bytes()
parsed_02 = parse_eml(raw_02)

print(f"Subject: '{parsed_02.subject}'")
print(f"From: '{parsed_02.from_address}'")
print(f"Body text length: {len(parsed_02.body_text)} chars")
print(f"Body snippet:\n{parsed_02.body_text[:300]}...\n")

clf = get_classifier()
tfidf = clf.pipeline.named_steps["tfidf"]
full_text = f"{parsed_02.subject}\n{parsed_02.body_text}"
x_sparse = tfidf.transform([full_text])
non_zero_indices = x_sparse.indices
print(f"TF-IDF Non-zero features count: {len(non_zero_indices)}")

active_terms = [clf.feature_names[i] for i in non_zero_indices[:15]]
print(f"Sample 15 active TF-IDF terms:\n  {active_terms}")

pred_02 = clf.predict(parsed_02)
print(f"\nML Predicted Class: {pred_02.predicted_class} ({pred_02.notes[0]})")
print("Calibrated Probabilities across 5 classes:")
for k, v in pred_02.probabilities.items():
    print(f"  - {k:<12}: {v:.6f}")

print("\nTop 10 SHAP Features for Predicted Class:")
for feat in pred_02.top_features[:10]:
    print(f"  - {feat.feature:<25}: val={feat.value:.4f}, contrib={feat.contribution:+.4f}, dir={feat.direction}")

print(f"\nAI Detector Results:")
print(f"  Perplexity: {pred_02.ai_detector.get('perplexity')}")
print(f"  Burstiness: {pred_02.ai_detector.get('burstiness')}")
print(f"  AI Probability: {pred_02.ai_detector.get('ai_generated_probability')}")
print(f"  Verdict: {pred_02.ai_detector.get('verdict')} ({pred_02.ai_detector.get('confidence')})")

print("\nGeoIP Hop Resolutions:")
for idx, hop in enumerate(parsed_02.received_chain):
    geo = resolve_ip(hop.from_ip) if hop.from_ip else None
    print(f"  Hop {idx+1} [IP: {hop.from_ip}]: resolved={geo.resolved if geo else False}, src={geo.source if geo else 'none'}, country={geo.country if geo else ''}, asn={geo.asn if geo else ''}")

nlp_signals = check_language(parsed_02)
print("\nNLP Signals Triggered:")
for s in nlp_signals:
    print(f"  {s.id:<25}: weight={s.weight:.3f}, title='{s.title}'")
    print(f"    Evidence: {s.evidence}")

case_02 = build_case(raw_02, filename="02-bec-wire-transfer.eml")
investigate(case_02)
print(f"\nFinal Investigated Case Verdict: label='{case_02.verdict.label}', risk_score={case_02.verdict.risk_score:.1f}, confidence={case_02.verdict.confidence:.1f}")

print("\n" + "=" * 70)
print("--- 6b. Deep Inspection of 05-ai-generated-spearphish.eml ---")
print("=" * 70)
eml_05_path = REPO_ROOT / "data" / "demo" / "05-ai-generated-spearphish.eml"
raw_05 = eml_05_path.read_bytes()
parsed_05 = parse_eml(raw_05)

print(f"Subject: '{parsed_05.subject}'")
print(f"From: '{parsed_05.from_address}'")
print(f"Body snippet:\n{parsed_05.body_text[:300]}...\n")

pred_05 = clf.predict(parsed_05)
print(f"ML Predicted Class: {pred_05.predicted_class} ({pred_05.notes[0]})")
print("Calibrated Probabilities:")
for k, v in pred_05.probabilities.items():
    print(f"  - {k:<12}: {v:.6f}")

print("\nTop 10 SHAP Features pushing to class 0 (Benign):")
for feat in pred_05.top_features[:10]:
    print(f"  - {feat.feature:<25}: val={feat.value:.4f}, contrib={feat.contribution:+.4f}, dir={feat.direction}")

case_05 = build_case(raw_05, filename="05-ai-generated-spearphish.eml")
investigate(case_05)
print(f"\nFinal Case Verdict for 05: label='{case_05.verdict.label}', risk_score={case_05.verdict.risk_score:.1f}, confidence={case_05.verdict.confidence:.1f}")

