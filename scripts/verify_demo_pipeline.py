#!/usr/bin/env python3
"""Run full production forensic pipeline across all demo emails in data/demo/."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.geoip.resolver import resolve_ip
from app.ingestion.parser import parse_eml
from app.ml.predict import get_classifier

def main() -> int:
    demo_dir = REPO_ROOT / "data" / "demo"
    eml_files = sorted(demo_dir.glob("*.eml"))

    print("\n" + "=" * 115)
    print("MAILTRACE PRODUCTION PIPELINE VERIFICATION REPORT (DATA/DEMO)")
    print("=" * 115)
    print(f"{'Filename':<32} | {'Class':<12} | {'Probabilities (B/S/P/BEC/M)':<30} | {'AI Detector':<16} | {'GeoIP Src':<10} | {'Latency':<8}")
    print("-" * 115)

    clf = get_classifier()
    all_passed = True

    for eml_path in eml_files:
        raw_bytes = eml_path.read_bytes()
        t0 = time.perf_counter()

        parsed = parse_eml(raw_bytes)
        pred = clf.predict(parsed)

        # Test GeoIP on first public received hop or standard lookup
        geo_src = "none"
        for hop in parsed.received_chain:
            if hop.from_ip and not hop.is_private_ip:
                geo = resolve_ip(hop.from_ip)
                geo_src = geo.source
                break
        if geo_src in ("none", "unavailable"):
            geo = resolve_ip("8.8.8.8")
            geo_src = geo.source

        duration_ms = (time.perf_counter() - t0) * 1000.0

        p = pred.probabilities or {}
        p_str = f"{p.get('benign',0):.2f}/{p.get('suspicious',0):.2f}/{p.get('phishing',0):.2f}/{p.get('bec',0):.2f}/{p.get('malware',0):.2f}"
        ai_str = f"{pred.ai_detector.get('verdict','?')[:8]} (p={pred.ai_detector.get('ai_generated_probability',0):.2f})"
        class_str = f"{pred.predicted_class}:{pred.notes[0].split()[1] if pred.notes else '?'}"

        print(f"{eml_path.name:<32} | {class_str:<12} | {p_str:<30} | {ai_str:<16} | {geo_src:<10} | {duration_ms:<6.1f}ms")

        if duration_ms > 200.0:
            print(f"  [WARNING] Latency exceeded 200ms: {duration_ms:.1f}ms")
            all_passed = False

    print("=" * 115)

    # Check metrics.json
    metrics_file = REPO_ROOT / "ml" / "models" / "metrics.json"
    if metrics_file.exists():
        m_data = json.loads(metrics_file.read_text(encoding="utf-8"))
        print(f"metrics.json -> synthetic: {m_data.get('synthetic')} | model: {m_data.get('model_name')}")
        if m_data.get("synthetic") is not False:
            print("  [ERROR] metrics.json has synthetic != false")
            all_passed = False

    print("\nVerification status:", "PASSED" if all_passed else "FAILED")
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
