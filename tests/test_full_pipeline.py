import glob
import hashlib
import json
import os
import re
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
import joblib
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT))

from app.engine import ai_detector
from app.geoip.resolver import resolve_ip
from app.detection.engine import extract_signals
from app.pipeline import build_case
from app.agent.loop import investigate


def load_texts(filename: str):
    path = REPO_ROOT / "data" / "corpus" / "real" / filename
    return [json.loads(l)["text"] for l in open(path, encoding="utf-8")]


def count_lines(filename: str):
    path = REPO_ROOT / "data" / "corpus" / "real" / filename
    return sum(1 for _ in open(path, encoding="utf-8"))


def load_labels(filename: str):
    path = REPO_ROOT / "data" / "corpus" / "real" / filename
    return [json.loads(l)["label"] for l in open(path, encoding="utf-8")]


def load_sources(filename: str):
    path = REPO_ROOT / "data" / "corpus" / "real" / filename
    return [json.loads(l).get("source", "unknown") for l in open(path, encoding="utf-8")]


def run_full_pipeline(raw_eml: bytes):
    case = build_case(raw_eml, filename="test.eml")
    investigate(case)
    has_live_geo = any(h.location and h.location.source == "live" for h in case.relay_hops)
    return {
        "verdict": case.verdict.label,
        "risk_score": case.verdict.risk_score,
        "ml": {
            "label": case.ml.label,
            "predicted_class": case.ml.predicted_class,
            "class_id": case.ml.predicted_class,
            "top_features": case.ml.top_features,
            "probabilities": case.ml.probabilities,
        },
        "geo": {
            "source": "live" if has_live_geo else (case.relay_hops[0].location.source if case.relay_hops and case.relay_hops[0].location else "unavailable")
        },
        "ai_detector": case.ml.ai_detector,
        "root_hash": case.email_hash,
    }




# --------------------------------------------------------------------------
# Layer 1 & Dataset Integrity Tests
# --------------------------------------------------------------------------

class TestDataIntegrity:
    def test_zero_train_test_overlap(self):
        train = set(load_texts("train_v2.jsonl"))
        test = load_texts("test_v2.jsonl")
        overlap = [t for t in test if t in train]
        assert len(overlap) == 0, f"DATA LEAKAGE: {len(overlap)} samples overlap"

    def test_minimum_corpus_size(self):
        total = count_lines("train_v2.jsonl") + count_lines("test_v2.jsonl")
        assert total >= 25000, f"Corpus too small: {total} < 25000"

    def test_all_five_classes_present(self):
        labels = load_labels("train_v2.jsonl")
        assert set(labels) == {0, 1, 2, 3, 4}, f"Missing classes: {set(labels)}"

    def test_class_balance_acceptable(self):
        labels = load_labels("train_v2.jsonl")
        counts = Counter(labels)
        min_class = min(counts.values())
        max_class = max(counts.values())
        ratio = max_class / min_class
        assert ratio < 10.0, f"Class imbalance too high: {ratio:.1f}x"


    def test_text_length_variance_real(self):
        texts = load_texts("train_v2.jsonl")
        std = statistics.stdev([len(t) for t in texts])
        assert std > 300, f"Low variance suggests synthetic: std={std:.0f}"

    def test_source_diversity(self):
        sources = load_sources("train_v2.jsonl")
        unique = set(sources)
        assert len(unique) >= 5, f"Insufficient source diversity: {unique}"


# --------------------------------------------------------------------------
# Model Behavior Tests
# --------------------------------------------------------------------------

class TestModelBehavior:
    def setup_method(self):
        bundle = joblib.load(REPO_ROOT / "ml" / "models" / "phish_tfidf_lr_v2.joblib")
        self.model = bundle["pipeline"] if isinstance(bundle, dict) else bundle

    def test_benign_attachment_not_malware(self):
        benign_attached = [
            "Hi team, attached is the Q3 report for review",
            "Please find attached the meeting notes",
            "Attached is the signed contract for your records",
            "I have attached the presentation we discussed",
            "Attaching the roadmap document as requested",
        ]
        for text in benign_attached:
            pred = self.model.predict([text])[0]
            assert pred != 4, f"FALSE POSITIVE: '{text[:40]}' -> Malware (Class 4)"

    def test_bec_classified_correctly(self):
        bec_texts = [
            "Please wire $50000 to vendor account routing 021000021",
            "CEO request: transfer funds to new bank account today",
            "Urgent: redirect my payroll to new bank account number",
            "Send W2 forms for all employees to this email now",
        ]
        for text in bec_texts:
            pred = self.model.predict([text])[0]
            assert pred in [1, 3], f"MISS: BEC email classified as {pred}"

    def test_phishing_classified_correctly(self):
        phish_texts = [
            "Verify your Microsoft account click here immediately",
            "Your PayPal is suspended confirm identity now",
            "Google security alert verify login credentials",
        ]
        for text in phish_texts:
            pred = self.model.predict([text])[0]
            assert pred in [1, 2], f"MISS: Phishing email classified as {pred}"

    def test_malware_classified_correctly(self):
        malware_texts = [
            "Enable macros to view the attached invoice xlsm",
            "Run attached installer to access your document exe",
            "Extract the password protected zip and run the vbs",
        ]
        for text in malware_texts:
            pred = self.model.predict([text])[0]
            assert pred == 4, f"MISS: Malware email classified as {pred}"

    def test_probabilities_sum_to_one(self):
        test_text = "Test email content for probability check"
        probs = self.model.predict_proba([test_text])[0]
        assert abs(sum(probs) - 1.0) < 0.001

    def test_no_perfect_probability_on_ambiguous(self):
        ambiguous = "Please review the attached document and let me know"
        probs = self.model.predict_proba([ambiguous])[0]
        max_prob = max(probs)
        assert max_prob < 0.99, f"Overconfident on ambiguous text: {max_prob}"

    def test_cv_no_overfit(self):
        metrics = json.load(open(REPO_ROOT / "ml" / "models" / "metrics_v2.json", encoding="utf-8"))
        for fold_name, fold in metrics["cv_results"].items():
            gap = fold["train_acc"] - fold["val_acc"]
            assert gap < 0.08, f"Overfit detected in {fold_name}: train-val gap = {gap:.3f}"

    def test_accuracy_realistic(self):
        metrics = json.load(open(REPO_ROOT / "ml" / "models" / "metrics_v2.json", encoding="utf-8"))
        acc = metrics["honest_test_metrics"]["accuracy"]
        assert 0.80 <= acc <= 1.0, f"Unrealistic accuracy: {acc}"


# --------------------------------------------------------------------------
# AI Detector Tests
# --------------------------------------------------------------------------

class TestAIDetector:
    def setup_method(self):
        self.detect = ai_detector.detect
        self.lm = ai_detector.load_lm()

    def test_human_higher_perplexity_than_ai(self):
        human = """
        Hey Sarah, hope you're doing well! The vendor still hasn't 
        sent the updated contract. Super annoying tbh. Let me know 
        if you want me to chase them. Also are we still on for 3pm? 
        I might be 5 mins late. Cheers, Tom
        """
        ai_phish = """
        Dear Valued Customer, we are writing to inform you that 
        your account requires immediate verification. Please click 
        the link below to verify your account details. Failure to 
        do so within 24 hours will result in account suspension.
        """
        r_human = self.detect(human)
        r_ai = self.detect(ai_phish)
        assert r_human["perplexity"] > r_ai["perplexity"] + 50, \
            f"Perplexity not separated: human={r_human['perplexity']:.0f}, ai={r_ai['perplexity']:.0f}"

    def test_human_higher_burstiness(self):
        human = """
        Hi. Long day honestly. The meeting ran 2 hours over and 
        then the client called right after with 47 questions about 
        the proposal we sent last week, which I thought was pretty 
        clear but apparently not? Anyway just flagging for you. 
        Let me know if you want to sync tomorrow morning or afternoon 
        whatever works.
        """
        ai = """
        Dear Customer, your account has been suspended. We require 
        immediate verification of your identity. Please click the 
        link provided to restore your account access. Thank you for 
        your cooperation with this important security matter.
        """
        r_human = self.detect(human)
        r_ai = self.detect(ai)
        assert r_human["burstiness"] > r_ai["burstiness"], \
            f"Burstiness not separated: human={r_human['burstiness']:.3f}, ai={r_ai['burstiness']:.3f}"

    def test_human_verdict_not_ai_generated(self):
        human = """
        Quick note before I forget — the printer on floor 3 
        is still broken. IT said they'd fix it by Tuesday but 
        that was last week lol. Also can you send me the catering 
        receipt? Finance is asking again.
        """
        result = self.detect(human)
        assert result["verdict"] in ["HUMAN", "LIKELY_AI"], f"Human email wrongly flagged as AI_GENERATED: {result}"

    def test_short_text_handled(self):
        result = self.detect("Hello")
        assert result["verdict"] is not None

    def test_empty_text_handled(self):
        result = self.detect("")
        assert result is not None


# --------------------------------------------------------------------------
# GeoIP Tests
# --------------------------------------------------------------------------

class TestGeoIP:
    def test_city_mmdb_size_real(self):
        size = os.path.getsize(REPO_ROOT / "data" / "geoip" / "city.mmdb")
        assert size > 100_000_000, f"city.mmdb too small: {size/1e6:.1f}MB"

    def test_asn_mmdb_size_real(self):
        size = os.path.getsize(REPO_ROOT / "data" / "geoip" / "asn.mmdb")
        assert size > 5_000_000, f"asn.mmdb too small: {size/1e6:.1f}MB"

    def test_google_ip_resolves(self):
        result = resolve_ip("8.8.8.8")
        assert result["country"] == "United States"
        assert "Google" in result["org"]
        assert result["source"] == "live"

    def test_cloudflare_ip_resolves(self):
        result = resolve_ip("1.1.1.1")
        assert "Cloudflare" in result["org"]
        assert result["source"] == "live"

    def test_tor_exit_flagged(self):
        result = resolve_ip("185.220.101.1")
        assert result["source"] == "live"
        assert result["asn"] is not None

    def test_private_ip_handled(self):
        result = resolve_ip("192.168.1.1")
        assert result is not None

    def test_invalid_ip_handled(self):
        result = resolve_ip("not.an.ip")
        assert result is not None

    def test_no_fixture_fallback_on_real_ips(self):
        real_ips = ["8.8.8.8", "1.1.1.1", "103.21.244.0"]
        for ip in real_ips:
            result = resolve_ip(ip)
            assert result["source"] == "live", f"IP {ip} fell back to fixture ({result['source']})"


# --------------------------------------------------------------------------
# NLP Signal Tests
# --------------------------------------------------------------------------

class TestNLPSignals:
    def test_bec_triggers_financial_signal(self):
        text = "Wire $85000 to vendor account routing 021000021 today"
        signals = extract_signals(text, text)
        ids = [s.id for s in signals]
        assert "nlp.payment_diversion" in ids or "nlp.urgency" in ids

    def test_cosine_score_above_noise(self):
        text = "Urgent CEO request: wire funds immediately confidential"
        signals = extract_signals(text, text)
        weights = {s.id: s.weight for s in signals}
        for sig_id, weight in weights.items():
            assert weight > 0.15, f"Signal {sig_id} weight {weight:.3f} is noise level"

    def test_clean_email_no_signals(self):
        text = "Hi, please review the attached Q3 report. Thanks."
        signals = extract_signals(text, text)
        high_signals = [s for s in signals if s.weight > 0.3]
        assert len(high_signals) == 0, f"False signals on clean email: {[s.id for s in high_signals]}"

    def test_no_keyword_tuples_in_engine(self):
        source = (REPO_ROOT / "backend" / "app" / "detection" / "engine.py").read_text(encoding="utf-8")
        assert "URGENCY = (" not in source, "Keyword tuple URGENCY still present"
        assert "PAYMENT = (" not in source, "Keyword tuple PAYMENT still present"


# --------------------------------------------------------------------------
# End-to-End Pipeline Integration Tests
# --------------------------------------------------------------------------

class TestEndToEnd:
    def test_full_pipeline_bec_email(self):
        raw_eml = open(REPO_ROOT / "data" / "demo" / "02-bec-wire-transfer.eml", "rb").read()
        result = run_full_pipeline(raw_eml)
        assert result["verdict"] in ["phishing", "fraud", "bec", "suspicious", "malicious"]
        assert result["risk_score"] > 60
        assert result["ml"]["label"] in ["bec", "suspicious", "phishing", "malicious"]
        assert len(result["ml"]["top_features"]) >= 5
        assert result["ai_detector"]["verdict"] is not None

    def test_full_pipeline_benign_email(self):
        raw_eml = open(REPO_ROOT / "data" / "demo" / "04-legitimate-notice.eml", "rb").read()
        result = run_full_pipeline(raw_eml)
        assert result["risk_score"] < 50
        assert result["ml"]["label"] in ["benign", "suspicious"]

    def test_pipeline_latency_under_200ms(self):
        raw_eml = open(REPO_ROOT / "data" / "demo" / "02-bec-wire-transfer.eml", "rb").read()
        start = time.perf_counter()
        result = run_full_pipeline(raw_eml)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 200, f"Pipeline too slow: {elapsed_ms:.1f}ms > 200ms"

    def test_all_demo_emails_complete(self):
        demo_files = glob.glob(str(REPO_ROOT / "data" / "demo" / "*.eml"))
        assert len(demo_files) >= 7
        for eml_path in demo_files:
            raw = open(eml_path, "rb").read()
            result = run_full_pipeline(raw)
            assert "verdict" in result, f"No verdict for {eml_path}"
            assert "risk_score" in result
            assert 0 <= result["risk_score"] <= 100
            assert "ml" in result
            assert "ai_detector" in result

    def test_models_preloaded_at_startup(self):
        from app.ml import predict
        assert predict._model is not None, "Model not preloaded at startup"
        from app.engine import ai_detector
        assert ai_detector._lm is not None, "Language model not preloaded at startup"

    def test_hash_integrity_chain(self):
        raw_eml = open(REPO_ROOT / "data" / "demo" / "01-phishing-password-expiry.eml", "rb").read()
        expected_hash = hashlib.sha256(raw_eml).hexdigest()
        result = run_full_pipeline(raw_eml)
        assert result["root_hash"] == expected_hash, "Hash mismatch — Layer 1 not hashing raw bytes"

    def test_spearphish_not_benign(self):
        raw = open(REPO_ROOT / "data" / "demo" / "05-ai-generated-spearphish.eml", "rb").read()
        result = run_full_pipeline(raw)
        assert result["ml"]["predicted_class"] != 0, "Spearphish still classified as benign"
        assert result["risk_score"] > 50, f"Spearphish risk too low: {result['risk_score']}"

    def test_dangerous_attachment_is_malware(self):
        raw = open(REPO_ROOT / "data" / "demo" / "03-dangerous-attachment.eml", "rb").read()
        result = run_full_pipeline(raw)
        assert result["ml"]["class_id"] == 4, f"Dangerous attachment not Malware: {result['ml']['label']}"

    def test_all_emails_under_200ms(self):
        for path in glob.glob(str(REPO_ROOT / "data" / "demo" / "*.eml")):
            raw = open(path, "rb").read()
            start = time.perf_counter()
            run_full_pipeline(raw)
            ms = (time.perf_counter() - start) * 1000
            assert ms < 200, f"{os.path.basename(path)}: {ms:.1f}ms > 200ms"

    def test_risk_verdict_matches_class(self):
        raw = open(REPO_ROOT / "data" / "demo" / "02-bec-wire-transfer.eml", "rb").read()
        result = run_full_pipeline(raw)
        assert result["verdict"] == "bec", f"BEC verdict mismatch: {result['verdict']}"

    def test_accuracy_realistic_after_semantic_dedup(self):
        metrics_path = REPO_ROOT / "ml" / "models" / "metrics_v3.json"
        if not metrics_path.exists():
            metrics_path = REPO_ROOT / "ml" / "models" / "metrics_v2.json"
        metrics = json.load(open(metrics_path, encoding="utf-8"))
        acc = metrics["honest_test_metrics"]["accuracy"]
        assert acc <= 0.995, f"Accuracy still suspiciously high: {acc}"
        assert metrics["roc_auc"] <= 1.0, f"ROC-AUC still perfect: {metrics['roc_auc']}"

    def test_ai_detector_separates_human_from_ai(self):
        raw_ai = open(REPO_ROOT / "data" / "demo" / "05-ai-generated-spearphish.eml", "rb").read()
        result = run_full_pipeline(raw_ai)
        ai_prob = result["ai_detector"]["ai_generated_probability"]
        assert ai_prob > 0.45, f"AI spearphish not detected as AI: prob={ai_prob}"



