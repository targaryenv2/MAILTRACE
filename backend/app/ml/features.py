"""Turn a ParsedEmail into the two inputs the model consumes: a text document
and a fixed vector of engineered indicators.

Why both: text alone misses header forensics (SPF alignment, lookalike domains)
and headers alone miss the lure. Keeping the engineered features in the *same*
vector space as the tokens means one weight vector explains everything, which is
what makes the exact-Shapley attribution in ``explain.py`` cover the whole
decision rather than just the wording.
"""

from __future__ import annotations

import math
import re
from typing import Dict, List

from ..ingestion.parser import registrable, strip_html
from ..schemas import ParsedEmail

TOKEN_RE = re.compile(r"[a-z0-9$£€!?']+")

# Fixed order. Adding a key here changes the model dimension, so retrain.
META_KEYS: List[str] = [
    "meta:spf_fail",
    "meta:spf_unaligned",
    "meta:dkim_fail",
    "meta:dkim_missing",
    "meta:dmarc_fail",
    "meta:no_auth",
    "meta:reply_to_differs",
    "meta:return_path_differs",
    "meta:freemail_sender",
    "meta:punycode_sender",
    "meta:has_urls",
    "meta:many_urls",
    "meta:url_ip_literal",
    "meta:url_shortener",
    "meta:url_anchor_mismatch",
    "meta:url_offdomain",
    "meta:has_attachment",
    "meta:attach_executable",
    "meta:attach_macro",
    "meta:attach_double_ext",
    "meta:no_received_chain",
    "meta:long_relay_chain",
    "meta:no_message_id",
    "meta:html_only",
    "meta:subject_caps",
    "meta:short_body",
    "meta:long_body",
    "meta:many_recipients",
    "meta:no_recipients",
    "meta:digit_domain",
]


def document(parsed: ParsedEmail) -> str:
    """Flatten the parts of the message a language model of any kind should see.

    URL hosts are included as text because ``login-microsoft-verify.tk`` is a
    strong lexical signal in itself.
    """
    parts = [
        parsed.subject or "",
        parsed.from_name or "",
        parsed.from_domain or "",
        parsed.body_text or strip_html(parsed.body_html),
    ]
    parts += [u.domain for u in parsed.urls[:20]]
    parts += [(u.path or "")[:80] for u in parsed.urls[:20]]
    parts += [a.filename for a in parsed.attachments[:10]]
    return "\n".join(p for p in parts if p)


def tokenise(text: str, ngram: int = 2) -> List[str]:
    """Lowercased word unigrams plus contiguous n-grams up to ``ngram``.

    Bigrams matter here: "wire transfer" and "password expire" carry the signal,
    while "wire" and "password" on their own appear in ordinary mail too.
    """
    words = TOKEN_RE.findall(text.lower())
    out: List[str] = list(words)
    for n in range(2, max(2, ngram) + 1):
        out += [" ".join(words[i:i + n]) for i in range(len(words) - n + 1)]
    return out


def meta(parsed: ParsedEmail) -> Dict[str, float]:
    """Engineered indicators, all in [0, 1] so no feature scaling is needed."""
    a = parsed.auth
    from_reg = registrable(parsed.from_domain)
    urls = parsed.urls
    atts = parsed.attachments
    body = parsed.body_text or strip_html(parsed.body_html)
    letters = [c for c in (parsed.subject or "") if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / \
        len(letters) if len(letters) >= 8 else 0.0
    recips = len(parsed.to) + len(parsed.cc)
    rdom = registrable(parsed.reply_to.rsplit(
        "@", 1)[-1]) if parsed.reply_to else ""
    pdom = registrable(parsed.return_path.rsplit(
        "@", 1)[-1]) if parsed.return_path else ""
    freemail = from_reg in {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
        "protonmail.com", "yandex.com", "rediffmail.com", "mail.com",
    }
    v = {
        "meta:spf_fail": float(a.spf in {"fail", "softfail"}),
        "meta:spf_unaligned": float(a.spf == "pass" and a.spf_aligned is False),
        "meta:dkim_fail": float(a.dkim == "fail"),
        "meta:dkim_missing": float(a.dkim in {"none", "unknown"}),
        "meta:dmarc_fail": float(a.dmarc == "fail"),
        "meta:no_auth": float(a.dkim in {"none", "unknown"} and a.spf in {"none", "unknown"}),
        "meta:reply_to_differs": float(bool(rdom) and rdom != from_reg),
        "meta:return_path_differs": float(bool(pdom) and pdom != from_reg),
        "meta:freemail_sender": float(freemail),
        "meta:punycode_sender": float("xn--" in (parsed.from_domain or "")),
        "meta:has_urls": float(bool(urls)),
        "meta:many_urls": min(1.0, len(urls) / 15.0),
        "meta:url_ip_literal": float(any(u.is_ip_literal for u in urls)),
        "meta:url_shortener": float(any(u.is_shortener for u in urls)),
        "meta:url_anchor_mismatch": float(any(u.anchor_mismatch for u in urls)),
        "meta:url_offdomain": float(any(u.registrable_domain and u.registrable_domain != from_reg for u in urls)),
        "meta:has_attachment": float(bool(atts)),
        "meta:attach_executable": float(any(x.is_executable for x in atts)),
        "meta:attach_macro": float(any(x.is_macro_capable for x in atts)),
        "meta:attach_double_ext": float(any(x.double_extension for x in atts)),
        "meta:no_received_chain": float(not parsed.received_chain),
        "meta:long_relay_chain": min(1.0, len(parsed.received_chain) / 8.0),
        "meta:no_message_id": float(not parsed.message_id),
        "meta:html_only": float(bool(parsed.body_html) and not (parsed.body_text or "").strip()),
        "meta:subject_caps": caps,
        "meta:short_body": float(len(body) < 250),
        "meta:long_body": min(1.0, len(body) / 6000.0),
        "meta:many_recipients": min(1.0, recips / 25.0),
        "meta:no_recipients": float(recips == 0),
        "meta:digit_domain": float(bool(re.search(r"\d", from_reg.split(".")[0]))) if from_reg else 0.0,
    }
    return {k: round(float(v.get(k, 0.0)), 6) for k in META_KEYS}


def l2_norm(vec: Dict[int, float]) -> float:
    return math.sqrt(sum(x * x for x in vec.values()))


STRUCTURAL_FEATURE_NAMES = [
    "feat_suspicious_attachment_ext",
    "feat_enable_macro_content",
    "feat_url_count",
    "feat_url_shortener",
    "feat_financial_iban_swift_routing",
    "feat_currency_amounts",
    "feat_time_bound_urgency",
    "feat_today_eod_deadline",
    "feat_executive_authority_pattern",
    "feat_secrecy_confidential_pattern",
    "feat_text_length_ratio",
    "feat_exclamation_count",
    "feat_all_caps_word_count",
    # 8 New discriminating features for BEC vs Malware separation
    "feat_malware_file_ext_mentions",
    "feat_malware_execution_instructions",
    "feat_malware_password_protected_archive",
    "feat_bec_wire_transfer_account_details",
    "feat_bec_person_to_person_instruction",
    "feat_bec_confidentiality_no_attachment",
    "feat_malware_download_link_ext",
    "feat_malware_urgency_file_lure",
]

_RE_SUSP_EXT = re.compile(r"\b(?:xlsm|docm|pptm|iso|img|vbs|js|hta|wsf|scr|pif|exe|bat|cmd|apk)\b", re.I)
_RE_SUSP_CTX = re.compile(r"\b(?:attached|enclosed|attachment|archive|zip)\b.{0,35}\b(?:macro|xlsm|docm|vbs|script|executable|installer|iso|img|payload|run)\b", re.I)
_RE_ENABLE_MACRO = re.compile(r"\b(?:enable\s+content|enable\s+macro|macros?\s+required|enable\s+editing|run\s+the\s+vbs)\b", re.I)
_RE_SHORTENER = re.compile(r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly)\b", re.I)
_RE_FINANCIAL = re.compile(r"\b(?:wire\s+transfer\s+(?:to|instructions|details|funds|amount|request|payment|[\$£€]|\d)|(?:process|send|initiate|urgent)\s+wire\s+transfer|iban\b|swift\b|bic\b|routing\s+(?:number|no\.?)|account\s+(?:number|no\.?)|update\s+(?:my\s+)?(?:direct\s+deposit|payroll|bank)|redirect\s+(?:my\s+)?payroll|remittance\s+advice|beneficiary\s+bank|w-?2\s+(?:forms|tax))\b", re.I)

_RE_CURRENCY = re.compile(r"[\$£€]\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})+\s*(?:usd|eur|gbp|dollars)\b", re.I)
_RE_URGENCY = re.compile(r"\b(?:within\s+24\s+hours|immediate\s+action|urgent|act\s+now|action\s+required|final\s+notice|last\s+warning|suspended|confirm\s+identity|verify\s+(?:login|credentials|account))\b", re.I)
_RE_DEADLINE = re.compile(r"\b(?:today|before\s+end\s+of\s+day|by\s+5\s*pm|asap|right\s+away)\b", re.I)
_RE_EXECUTIVE = re.compile(r"\b(?:ceo|cfo|chief\s+executive|managing\s+director|board\s+of\s+directors|on\s+behalf\s+of\s+the\s+executive)\b", re.I)
_RE_SECRECY = re.compile(r"\b(?:confidential|do\s+not\s+discuss|keep\s+this\s+quiet|between\s+us|strictly\s+private|handle\s+personally)\b", re.I)

# 8 New regexes
_RE_MALWARE_EXT = re.compile(r"\.(xlsm|docm|pptm|xls|doc|vbs|js|exe|zip|rar|iso|img|one|chm|hta|bat|ps1|lnk)\b", re.I)
_RE_MALWARE_EXEC = re.compile(r"(enable (macro|editing|content)|allow (macro|content|permission)|run the (attached|file|installer)|extract and (run|open|execute)|double.click to (open|run|install))", re.I)
_RE_MALWARE_PWD = re.compile(r"password.{0,20}(protected|is|:)\s*[\w\d]+|(open|extract).{0,20}password", re.I)
_RE_BEC_WIRE = re.compile(r"(routing|account|swift|iban|bic).{0,30}(number|no\.?|code|:\s*\d|\d{4,})", re.I)
_RE_BEC_PERSON = re.compile(r"(please\s+(?:wire|transfer|send|process|remit)|need\s+you\s+to\s+(?:transfer|wire|send|process)|arrange\s+(?:payment|transfer|wire)|wire\s+[\$£€]?\d+)", re.I)

_RE_CONFIDENTIAL = re.compile(r"(confidential|do not (tell|discuss))", re.I)
_RE_MALWARE_LINK_EXT = re.compile(r"https?://[^\s]+\.(exe|zip|rar|iso|doc|xls|pdf|js)\b", re.I)
_RE_URGENT_WORD = re.compile(r"(urgent|immediately|today)", re.I)
_RE_ATTACH_WORD = re.compile(r"(attached|attachment|file|document)", re.I)
_RE_DANGEROUS_EXT = re.compile(r"\.(xlsm|docm|zip|exe|vbs)\b", re.I)


def extract_structural_features(texts: List[str]):
    """21 structural domain-specific features designed to discriminate classes and eliminate false positives."""
    import numpy as np
    feats = np.zeros((len(texts), len(STRUCTURAL_FEATURE_NAMES)), dtype=np.float32)

    for i, t in enumerate(texts):
        raw = t or ""
        lower = raw.lower()

        # 1. Suspicious attachment extension and payload execution context
        has_susp_ext = bool(_RE_SUSP_EXT.search(lower))
        has_susp_context = bool(_RE_SUSP_CTX.search(lower))
        feats[i, 0] = 1.0 if (has_susp_ext or has_susp_context) else 0.0

        # 2. Weaponized macro execution enablement
        feats[i, 1] = 1.0 if bool(_RE_ENABLE_MACRO.search(lower)) else 0.0

        # 3. URL count
        url_matches = len(re.findall(r"https?://|www\.", lower))
        feats[i, 2] = min(url_matches / 5.0, 1.0)

        # 4. URL shortener
        feats[i, 3] = 1.0 if bool(_RE_SHORTENER.search(lower)) else 0.0

        # 5. Financial banking diversion markers (Wire transfer/IBAN/SWIFT/Routing/Direct Deposit update)
        feats[i, 4] = 1.0 if bool(_RE_FINANCIAL.search(lower)) else 0.0

        # 6. Currency amounts ($ / EUR / GBP / USD)
        feats[i, 5] = 1.0 if bool(_RE_CURRENCY.search(lower)) else 0.0

        # 7. Time-bound urgency and account suspension / credential alert markers
        feats[i, 6] = 1.0 if bool(_RE_URGENCY.search(lower)) else 0.0

        # 8. Today / EOD deadline pressure
        feats[i, 7] = 1.0 if bool(_RE_DEADLINE.search(lower)) else 0.0

        # 9. Executive authority framing (CEO / CFO / Director / Board)
        feats[i, 8] = 1.0 if bool(_RE_EXECUTIVE.search(lower)) else 0.0

        # 10. Secrecy / process bypass framing
        feats[i, 9] = 1.0 if bool(_RE_SECRECY.search(lower)) else 0.0

        # 11. Text length ratio
        feats[i, 10] = min(len(raw) / 2500.0, 1.0)

        # 12. Exclamation count
        feats[i, 11] = min(raw.count("!") / 5.0, 1.0)

        # 13. All-caps word count
        words = raw.split()
        caps = sum(1 for w in words if len(w) >= 4 and w.isupper())
        feats[i, 12] = min(caps / 5.0, 1.0)

        # 14. Malware-specific: file extension mentions
        feats[i, 13] = 1.0 if bool(_RE_MALWARE_EXT.search(lower)) else 0.0

        # 15. Malware-specific: execution instructions
        feats[i, 14] = 1.0 if bool(_RE_MALWARE_EXEC.search(lower)) else 0.0

        # 16. Malware-specific: password protected archive
        feats[i, 15] = 1.0 if bool(_RE_MALWARE_PWD.search(lower)) else 0.0

        # 17. BEC-specific: wire transfer with account details
        feats[i, 16] = 1.0 if bool(_RE_BEC_WIRE.search(lower)) else 0.0

        # 18. BEC-specific: person-to-person instruction
        feats[i, 17] = 1.0 if bool(_RE_BEC_PERSON.search(lower)) else 0.0

        # 19. BEC-specific: confidentiality instruction (no attachment)
        feats[i, 18] = 1.0 if (bool(_RE_CONFIDENTIAL.search(lower)) and not bool(_RE_MALWARE_EXT.search(lower))) else 0.0

        # 20. Malware-specific: download link with file extension
        feats[i, 19] = 1.0 if bool(_RE_MALWARE_LINK_EXT.search(lower)) else 0.0

        # 21. Malware-specific: urgency + file = malware lure
        feats[i, 20] = 1.0 if (bool(_RE_URGENT_WORD.search(lower)) and bool(_RE_ATTACH_WORD.search(lower)) and bool(_RE_DANGEROUS_EXT.search(lower))) else 0.0

    return feats


