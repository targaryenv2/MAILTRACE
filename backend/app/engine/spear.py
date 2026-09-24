"""Spearphishing Detection Layer.

Detects sophisticated spearphishing that evades TF-IDF through professional/benign
surface language with subtle malicious asks.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Pre-compiled regexes for sub-millisecond execution (Bug 3 Fix 1)
_PROFESSIONAL_FRAMING_RE = re.compile(
    r'(following up|as discussed|as per our|as requested|'
    r'per your request|wanted to share|thought you might|'
    r'please find|kindly review|for your review|'
    r'hope this finds you|revised|comments against|two clauses)',
    re.IGNORECASE,
)

_LINK_OR_ATTACHMENT_RE = re.compile(
    r'(https?://|click here|open the|download|'
    r'attached|shared document|google doc|dropbox|'
    r'onedrive|sharepoint|shared workspace|open it here)',
    re.IGNORECASE,
)

_AUTHORITY_IMPERSONATION_RE = re.compile(
    r'(on behalf of|as discussed with|per instructions from|'
    r'requested by|directed by|authorized by|'
    r'following up on behalf|programme manager|manager,)',
    re.IGNORECASE,
)

_SOFT_URGENCY_RE = re.compile(
    r'(whenever you (get|have) a chance.{0,50}'
    r'(today|tonight|eod|cob|this afternoon|by \d)|'
    r'no (rush|hurry|pressure).{0,50}'
    r'(today|soon|asap|quickly|shortly|this)|'
    r'at your (earliest|convenience).{0,30}'
    r'(urgent|important|critical|priority)|'
    r'when convenient)',
    re.IGNORECASE,
)

_INTERNAL_LANG_RE = re.compile(
    r'(team|colleague|department|office|our company|'
    r'the organization|internally|our systems|shared workspace|clauses)',
    re.IGNORECASE,
)

_CREDENTIAL_ASK_RE = re.compile(
    r'(login|password|credentials|access|verify|'
    r'authenticate|sign in|your account|open it here|document in)',
    re.IGNORECASE,
)

_FINANCIAL_ASK_RE = re.compile(
    r'(payment|invoice|transfer|approve|authorize|'
    r'budget|funds|account)',
    re.IGNORECASE,
)

_AI_PHRASES = [
    re.compile(r'i hope (this|you are|this email)', re.IGNORECASE),
    re.compile(r'please (do not hesitate|feel free) to', re.IGNORECASE),
    re.compile(r'thank you for your (prompt|continued|kind|time)', re.IGNORECASE),
    re.compile(r'best regards', re.IGNORECASE),
    re.compile(r'i am writing (to|in)', re.IGNORECASE),
    re.compile(r'please (find|see) attached', re.IGNORECASE),
    re.compile(r'as per (our|the|your)', re.IGNORECASE),
    re.compile(r'kindly (note|be advised|confirm)', re.IGNORECASE),
    re.compile(r'thanks again for', re.IGNORECASE),
]


def detect_spearphish(text: str, ml_class: int, ml_prob: float) -> Dict[str, Any]:
    """Detects sophisticated spearphish that evades TF-IDF.

    Only activates when ML predicts Benign/Suspicious (class 0/1)
    with high confidence, meaning the model thinks it's safe.
    """
    if ml_class not in [0, 1]:
        return {
            "spearphish_detected": False,
            "score": 0.0,
            "signals": [],
            "upgraded_class": ml_class,
            "upgraded_label": None,
        }

    score = 0.0
    signals: List[str] = []

    # Pattern 1: Document/link request buried in professional text
    has_prof_framing = bool(_PROFESSIONAL_FRAMING_RE.search(text))
    has_link_or_att = bool(_LINK_OR_ATTACHMENT_RE.search(text))
    if has_prof_framing and has_link_or_att:
        score += 0.35
        signals.append("professional_framing_with_link")

    # Pattern 2: Impersonation through authority / name-dropping
    if bool(_AUTHORITY_IMPERSONATION_RE.search(text)):
        score += 0.25
        signals.append("authority_impersonation_soft")

    # Pattern 3: Urgency hidden in polite / soft language
    if bool(_SOFT_URGENCY_RE.search(text)):
        score += 0.20
        signals.append("soft_urgency_buried")

    # Pattern 4: Internal language with sensitive action / link opening
    has_internal = bool(_INTERNAL_LANG_RE.search(text))
    has_cred = bool(_CREDENTIAL_ASK_RE.search(text))
    has_fin = bool(_FINANCIAL_ASK_RE.search(text))
    if has_internal and (has_cred or has_fin):
        score += 0.30
        signals.append("internal_language_with_sensitive_ask")

    # Pattern 5: AI writing style markers
    ai_phrase_count = sum(1 for p in _AI_PHRASES if p.search(text))
    if ai_phrase_count >= 2:
        score += 0.15 * ai_phrase_count
        signals.append(f"ai_phrase_patterns:{ai_phrase_count}")

    spearphish_detected = score >= 0.45

    return {
        "spearphish_detected": spearphish_detected,
        "score": round(min(score, 1.0), 4),
        "signals": signals,
        "upgraded_class": 2 if spearphish_detected else ml_class,
        "upgraded_label": "phishing" if spearphish_detected else None,
    }
