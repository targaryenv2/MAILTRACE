import json, re, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

print("=" * 70)
print("LAYER 5: NLP COSINE SIMILARITY AUTHENTICITY")
print("=" * 70)

engine_path = REPO_ROOT / "backend" / "app" / "detection" / "engine.py"
print("\n--- 5a. Keyword / Cosine Similarity Patterns in detection/engine.py ---")
lines = engine_path.read_text(encoding="utf-8").splitlines()
patterns = ["cosine", "similarity", "URGENCY =", "PAYMENT =", "AUTHORITY =", "SECRECY =", "CREDENTIAL ="]

for idx, line in enumerate(lines):
    if any(p in line for p in patterns):
        print(f"Line {idx+1:>4}: {line.strip()[:100]}")

print("\n--- 5b. Direct Signal Extraction Test ---")
from app.detection.engine import check_language
from app.schemas import ParsedEmail

# Test 1: BEC text
bec_text = """
Hi, this is the CEO. I need you to process an urgent wire 
transfer of $85,000 to our new vendor immediately. 
Do not discuss with anyone, handle confidentially.
"""
parsed_bec = ParsedEmail(
    subject="Urgent wire transfer request from CEO",
    body_text=bec_text,
)

# Test 2: Clean text
clean_text = """
Please find attached the meeting notes from yesterday's 
product review session. Let me know if you have questions.
"""
parsed_clean = ParsedEmail(
    subject="Meeting notes: product review session",
    body_text=clean_text,
)

signals_bec = check_language(parsed_bec)
signals_clean = check_language(parsed_clean)

print("\nBEC Text Signals:")
if not signals_bec:
    print("  [NONE]")
for s in signals_bec:
    print(f"  Signal '{s.id}': weight={s.weight:.3f}, severity={s.severity}, title='{s.title}'")
    print(f"    Evidence: {s.evidence}")
    print(f"    Detail: {s.detail}")

print("\nClean Text Signals (Should be empty or minimal):")
if not signals_clean:
    print("  [NONE - Completely Clean]")
for s in signals_clean:
    print(f"  Signal '{s.id}': weight={s.weight:.3f}, severity={s.severity}, title='{s.title}'")
    print(f"    Evidence: {s.evidence}")
    print(f"    Detail: {s.detail}")

