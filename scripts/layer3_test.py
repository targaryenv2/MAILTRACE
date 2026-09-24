import json, os, statistics, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

print("=" * 70)
print("LAYER 3: AI DETECTOR AUTHENTICITY")
print("=" * 70)

print("\n--- 3a. Full backend/app/engine/ai_detector.py Source ---")
ai_file = REPO_ROOT / "backend" / "app" / "engine" / "ai_detector.py"
print(ai_file.read_text(encoding="utf-8"))

print("\n--- 3b. trigram_lm.json Inspection ---")
lm_path = REPO_ROOT / "ml" / "models" / "trigram_lm.json"
print(f"File exists: {lm_path.exists()}")
if lm_path.exists():
    lm_data = json.loads(lm_path.read_text(encoding="utf-8"))
    bigrams = lm_data.get("bigrams", {})
    trigrams = lm_data.get("trigrams", {})
    
    total_tri_transitions = sum(len(sub) for sub in trigrams.values())
    print(f"Vocab size: {len(lm_data.get('vocab', []))}")
    print(f"Number of unique bigram prefixes: {len(bigrams)}")
    print(f"Total unique trigram transitions: {total_tri_transitions}")
    
    print("\nSample 10 Bigram & Trigram transitions:")
    for prefix in list(trigrams.keys())[:10]:
        print(f"  Prefix {repr(prefix)} (count {bigrams.get(prefix, 0)}): {trigrams[prefix]}")

print("\n--- 3c. Probing AI Detector on Human vs AI text ---")
from app.engine.ai_detector import get_ai_detector

human_email = """
Hey Sarah, hope you're doing well! Wanted to follow up on 
the thing we discussed last Thursday — the vendor still 
hasn't sent the updated contract. Super annoying tbh. 
Let me know if you want me to chase them again or if you'd 
rather handle it yourself. Also are we still on for the 
3pm call? I might be 5 mins late coming from another meeting.
Cheers, Tom
"""

ai_email = """
Dear Valued Customer, I hope this message finds you well. 
We are writing to inform you that your account requires 
immediate verification. Please click the link below to 
verify your account details. Failure to do so within 
24 hours will result in account suspension. Thank you 
for your prompt attention to this matter. Best regards, 
Security Team.
"""

detector = get_ai_detector()
res_human = detector.analyze(human_email)
res_ai = detector.analyze(ai_email)

print("\nHuman Email Result:\n", json.dumps(res_human, indent=2))
print("\nAI Email Result:\n", json.dumps(res_ai, indent=2))

print("\n--- 3d. Manual Burstiness Math Verification ---")
human_sentences = [s.strip() for s in human_email.split('.') if s.strip()]
ai_sentences = [s.strip() for s in ai_email.split('.') if s.strip()]

def calc_burst(sentences):
    lengths = [len(s.split()) for s in sentences if len(s.split()) > 0]
    if len(lengths) < 2:
        return 0.0, lengths, 0.0, 0.0
    mu = statistics.mean(lengths)
    sigma = statistics.stdev(lengths)
    b = (sigma - mu) / (sigma + mu)
    return b, lengths, mu, sigma

b_h, lens_h, mu_h, sig_h = calc_burst(human_sentences)
b_a, lens_a, mu_a, sig_a = calc_burst(ai_sentences)

print(f"Human sentences ({len(lens_h)}): lengths={lens_h} | mean={mu_h:.2f} | std={sig_h:.2f} | Burstiness={b_h:.4f}")
print(f"AI sentences ({len(lens_a)}): lengths={lens_a} | mean={mu_a:.2f} | std={sig_a:.2f} | Burstiness={b_a:.4f}")

