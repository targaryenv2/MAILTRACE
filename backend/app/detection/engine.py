"""Rule-based detection: deterministic, explainable signals.

Scoring is log-odds, not a bag of points. Each triggered signal contributes a
weight in **log-odds units** (a weight of ln(9) ~ 2.197 means "this evidence
alone makes phishing 9x more likely"), the weights sum, and a logistic function
maps the total to 0-100:

    logit = w0 + sum(w_i for triggered signals)
    risk  = 100 / (1 + exp(-logit))

That is Naive-Bayes evidence combination written in the standard way, and it is
why the score saturates instead of running past 100 once six signals fire. The
prior ``w0`` is negative: an unremarkable email is benign until evidence moves
it.
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

from ..schemas import (
    MlPrediction,
    ParsedEmail,
    RelayHop,
    RISK_CLEAN,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    Signal,
    SOURCE_COMPUTED,
    Verdict,
    VERDICT_BENIGN,
    VERDICT_BEC,
    VERDICT_MALWARE,
    VERDICT_INDETERMINATE,
    VERDICT_LIKELY_BENIGN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
)

from ..ingestion.parser import registrable, strip_html

# Prior log-odds. exp(-2.6) ~ 0.074, i.e. we start from "about 7% of unremarkable
# mail in a reported-phishing queue is actually malicious" and let evidence move
# it. Tuned so a single weak signal cannot cross 50.
log = logging.getLogger(__name__)

# Prior log-odds.
PRIOR_LOGIT = -2.6

# Brands whose names are worth impersonating. Used for lookalike-domain
# distance.
PROTECTED_BRANDS = (
    "microsoft",
    "office365",
    "outlook",
    "onedrive",
    "sharepoint",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "paypal",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "docusign",
    "adobe",
    "zoom",
    "sbi",
    "hdfcbank",
    "icicibank",
    "axisbank",
    "paytm",
    "phonepe",
    "aadhaar",
    "uidai",
    "incometax",
    "gst",
    "irctc",
    "aicte",
    "nic",
    "gov",
)

# Unicode confusables that matter for domains. Keeping this explicit beats
# pulling in the full UTS-39 table for a demo, and every entry here is a real
# character seen in registered lookalike domains.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "ν": "v", "κ": "k",
    "ı": "i", "ł": "l", "ø": "o", "ǀ": "l", "0": "o", "1": "l", "3": "e",
    "4": "a", "5": "s", "7": "t", "rn": "m", "vv": "w",
}

# Rich multi-paragraph forensic reference anchor documents (Zero-Shot Cosine Space)
URGENCY_ANCHOR = """
urgent immediate action required respond immediately final notice
account suspended terminated deactivated failure to comply consequences
deadline expires today within 24 hours last warning critical alert
time sensitive do not delay act now before too late
access revoked unless respond immediately
final opportunity to verify information
failure to act will result in permanent suspension
do not ignore message requires immediate attention
"""

FINANCIAL_ANCHOR = """
wire transfer bank electronic funds remittance
payment required invoice outstanding balance overdue account number
routing number swift code iban bic beneficiary bank details
process payment immediately transfer funds urgently
direct deposit payroll change bank account update vendor payment
gift card purchase amazon apple itunes google play send codes
cryptocurrency bitcoin ethereum wallet address transfer
financial transaction settlement disbursement closing funds
"""

AUTHORITY_ANCHOR = """
chief executive officer ceo president managing director chairman
on behalf of executive team board of directors senior management
request comes directly from office of ceo
instructions from director confidential
human resources payroll finance team it security
manager requested action completed urgently
per company policy directed by senior leadership
do not discuss request with colleagues confidential
direct order from executive office immediate compliance
"""

CREDENTIAL_ANCHOR = """
verify account login credentials password reset security alert
click link to confirm identity suspicious activity detected
account compromised update password immediately
enter username and password to verify identity
security team requires verification of account details
google microsoft apple paypal bank login verification required
unusual sign in attempt detected verify immediately
two factor authentication required click to proceed
session expired login again to continue
"""

MALWARE_ANCHOR = """
enable macros to view macro execution required to open workbook
download and run payload executable installer program
password protected zip archive extract and run exe vbs hta wsf
enable editing enable content in excel to decrypt ledger
mount iso img container file to inspect delivery
allow permissions to execute script payload
"""

NLP_ANCHORS = {
    "urgency": URGENCY_ANCHOR,
    "financial": FINANCIAL_ANCHOR,
    "authority": AUTHORITY_ANCHOR,
    "credential": CREDENTIAL_ANCHOR,
    "malware": MALWARE_ANCHOR,
}

FREEMAIL = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "aol.com",
    "yandex.com",
    "mail.com",
    "gmx.com",
    "rediffmail.com",
    "zoho.com",
    "icloud.com",
    "live.com",
    "proton.me",
}
SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "gq",
    "cf",
    "tk",
    "ml",
    "buzz",
    "click",
    "link",
    "work",
    "support",
    "review",
    "country",
    "kim",
    "loan",
    "rest",
    "cam",
    "quest",
}


def levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming edit distance, O(len(a)*len(b)) time and
    O(min) space. Used for lookalike-domain scoring, so it has to be the real
    metric rather than a similarity heuristic."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for j, cb in enumerate(b, 1):
        cur = [j]
        for i, ca in enumerate(a, 1):
            cur.append(min(prev[i] + 1, cur[i - 1] +
                       1, prev[i - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(text: str) -> str:
    """Map a string to its confusable skeleton (UTS-39 idea, small table).

    ``micrоsоft`` with Cyrillic o and ``rnicrosoft`` both collapse to
    ``microsoft``, which is what makes the edit-distance comparison meaningful.
    """
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    for src, dst in CONFUSABLES.items():
        if len(src) > 1:
            text = text.replace(src, dst)
    return "".join(CONFUSABLES.get(c, c) for c in text)


def _count_terms(haystack: str, terms: Tuple[str, ...]) -> List[str]:
    return sorted({t for t in terms if t in haystack})


def _sig(sid: str, stype: str, title: str, result: str, weight: float,
         severity: str, category: str = "heuristic", evidence: str = "",
         detail: Optional[Dict] = None) -> Signal:
    return Signal(
        id=sid, signal_type=stype, title=title, result=result, weight=weight,
        severity=severity, category=category, evidence=evidence[:600],
        detail=detail or {}, source=SOURCE_COMPUTED,
    )


def check_authentication(parsed: ParsedEmail) -> List[Signal]:
    a = parsed.auth
    out: List[Signal] = []
    if a.dmarc == "fail":
        out.append(_sig(
            "auth.dmarc_fail", "dmarc", "DMARC failed",
            "fail (policy=%s)" % (a.dmarc_policy or "unknown"), 2.30, RISK_HIGH,
            "authentication",
            "No aligned SPF or DKIM pass for the visible From domain %s." % a.from_domain,
            {"policy": a.dmarc_policy, "spf": a.spf, "dkim": a.dkim},
        ))
    elif a.dmarc == "pass":
        out.append(_sig("auth.dmarc_pass", "dmarc", "DMARC passed", "pass", -1.60,
                        RISK_CLEAN, "authentication",
                        "An aligned SPF or DKIM pass was present for %s." % a.from_domain))
    if a.spf in {"fail", "softfail"}:
        out.append(
            _sig(
                "auth.spf_fail",
                "spf",
                "SPF %s" %
                a.spf,
                a.spf,
                1.20,
                RISK_MEDIUM,
                "authentication",
                "Sending host is not authorised by %s SPF policy." %
                (a.spf_domain or "the envelope domain")))
    if a.spf == "pass" and a.spf_aligned is False:
        # The single most misread header in email: pass, but for the wrong
        # domain.
        out.append(
            _sig(
                "auth.spf_unaligned",
                "spf",
                "SPF passed but is not aligned",
                "pass, unaligned",
                1.55,
                RISK_HIGH,
                "authentication",
                "SPF authenticated %s while the visible From is %s, so the pass says "
                "nothing about the displayed sender." %
                (a.spf_domain,
                 a.from_domain),
            ))
    if a.dkim == "fail":
        out.append(
            _sig(
                "auth.dkim_fail",
                "dkim",
                "DKIM signature failed",
                "fail",
                1.40,
                RISK_MEDIUM,
                "authentication",
                "Body or headers were altered in transit, or the signature is forged."))
    if a.dkim == "none" and a.spf in {"none", "unknown"}:
        out.append(
            _sig(
                "auth.no_auth",
                "auth",
                "No sender authentication present",
                "no SPF and no DKIM",
                1.10,
                RISK_MEDIUM,
                "authentication",
                "Neither SPF nor DKIM was evaluated for this message."))
    if a.arc_chain == "fail":
        out.append(
            _sig(
                "auth.arc_fail",
                "arc",
                "ARC chain invalid",
                "fail",
                0.90,
                RISK_MEDIUM,
                "authentication",
                "Forwarding chain cannot be trusted to preserve the original result."))
    return out


def check_identity(parsed: ParsedEmail) -> List[Signal]:
    """Display-name spoofing, lookalike domains, reply-to divergence."""
    out: List[Signal] = []
    name = (parsed.from_name or "").strip()
    addr = parsed.from_address or ""
    dom = parsed.from_domain or ""
    reg = registrable(dom)

    # Display name contains an email address different from the real one.
    m = re.search(r"[\w.+-]+@[\w.-]+\.\w+", name)
    if m and m.group(0).lower() != addr:
        out.append(
            _sig(
                "id.name_contains_other_address",
                "display_name",
                "Display name contains a different address",
                m.group(0),
                2.10,
                RISK_HIGH,
                evidence="Display name shows %s but the envelope address is %s." %
                (m.group(0),
                 addr),
            ))
    # Display name claims a brand the sending domain has no relationship with.
    sk_name = skeleton(name)
    for brand in PROTECTED_BRANDS:
        if brand in sk_name and brand not in skeleton(reg):
            out.append(
                _sig(
                    "id.brand_impersonation",
                    "display_name",
                    "Display name impersonates a known brand",
                    brand,
                    1.90,
                    RISK_HIGH,
                    evidence="Display name %r references %s but the mail is from %s." %
                    (name,
                     brand,
                     dom or "an unknown domain"),
                    detail={
                        "brand": brand,
                        "sending_domain": dom},
                ))
            break
    # Lookalike sending domain: near-miss on a protected brand after
    # skeletonising.
    label = skeleton(reg.split(".")[0]) if reg else ""
    if label:
        for brand in PROTECTED_BRANDS:
            d = levenshtein(label, brand)
            if 0 < d <= max(1, len(brand) // 5) and label != brand:
                out.append(
                    _sig(
                        "id.lookalike_domain",
                        "homoglyph",
                        "Sending domain is a lookalike of %s" %
                        brand,
                        "%s (edit distance %d)" %
                        (reg,
                         d),
                        2.40,
                        RISK_CRITICAL,
                        evidence="Confusable skeleton of %s is %r, %d edit(s) from %r." %
                        (reg,
                         label,
                         d,
                         brand),
                        detail={
                            "brand": brand,
                            "distance": d,
                            "skeleton": label},
                    ))
                break
    if dom and skeleton(dom) != dom.lower():
        out.append(
            _sig(
                "id.confusable_chars",
                "homoglyph",
                "Sending domain contains confusable characters",
                dom,
                2.20,
                RISK_CRITICAL,
                evidence="Normalises to %s." %
                skeleton(dom)))
    if "xn--" in dom:
        out.append(
            _sig(
                "id.punycode_sender",
                "homoglyph",
                "Punycode sender domain",
                dom,
                1.80,
                RISK_HIGH,
                evidence="IDN homograph attacks use punycode encoding."))
    if parsed.reply_to and parsed.reply_to != addr:
        rdom = registrable(parsed.reply_to.rsplit("@", 1)[-1])
        if rdom != reg:
            sev = RISK_HIGH if rdom in FREEMAIL else RISK_MEDIUM
            out.append(
                _sig(
                    "id.replyto_divergence",
                    "reply_to",
                    "Reply-To points to another domain",
                    parsed.reply_to,
                    1.70 if rdom in FREEMAIL else 1.20,
                    sev,
                    evidence="Replies would go to %s instead of %s%s." %
                    (parsed.reply_to,
                     addr,
                     " (free webmail)" if rdom in FREEMAIL else ""),
                    detail={
                        "reply_to_domain": rdom,
                        "freemail": rdom in FREEMAIL},
                ))
    if parsed.return_path:
        pdom = registrable(parsed.return_path.rsplit("@", 1)[-1])
        if pdom and pdom != reg:
            out.append(
                _sig(
                    "id.returnpath_mismatch",
                    "return_path",
                    "Return-Path domain differs from From",
                    parsed.return_path,
                    0.80,
                    RISK_LOW,
                    evidence="Bounces would go to %s, not %s." %
                    (pdom,
                     reg)))
    if reg in SUSPICIOUS_TLDS or (
            reg and reg.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS):
        out.append(_sig("id.suspicious_tld", "domain", "Sender uses a high-abuse TLD", reg, 0.85, RISK_MEDIUM,
                   evidence="TLD .%s has a disproportionate share of abuse registrations." % reg.rsplit(".", 1)[-1]))
    return out


# Cached vectorizer and reference embeddings
_ANCHORS_VECTORIZER = None
_ANCHORS_MATRIX = None
_ANCHOR_KEYS = list(NLP_ANCHORS.keys())


def _init_anchors_cache():
    global _ANCHORS_VECTORIZER, _ANCHORS_MATRIX
    if _ANCHORS_VECTORIZER is None:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
            docs = [NLP_ANCHORS[k] for k in _ANCHOR_KEYS]
            mat = vec.fit_transform(docs)
            _ANCHORS_VECTORIZER = vec
            _ANCHORS_MATRIX = mat
        except Exception as e:
            log.warning(f"Failed to initialize NLP anchors cache: {e}")


def _get_zero_shot_similarities(text: str) -> Dict[str, float]:
    """Compute zero-shot cosine similarity against rich multi-paragraph reference anchors."""
    _init_anchors_cache()
    if not _ANCHORS_VECTORIZER or not text or len(text.strip()) < 5:
        return {k: 0.0 for k in _ANCHOR_KEYS}

    try:
        from sklearn.metrics.pairwise import cosine_similarity
        text_vec = _ANCHORS_VECTORIZER.transform([text])
        sims = cosine_similarity(text_vec, _ANCHORS_MATRIX)[0]
        return {_ANCHOR_KEYS[i]: float(sims[i]) for i in range(len(_ANCHOR_KEYS))}
    except Exception:
        return {k: 0.0 for k in _ANCHOR_KEYS}


def extract_signals(subject: str, body: str) -> List[Signal]:
    """Pure cosine-similarity based social engineering signal extraction."""
    out: List[Signal] = []
    blob = f"{subject or ''}\n{body or ''}".strip().lower()
    if not blob:
        return out

    sims = _get_zero_shot_similarities(blob)

    # 1. Urgency & Pressure
    if sims.get("urgency", 0.0) >= 0.08:
        score = sims["urgency"]
        w = round(min(1.80, max(0.40, score * 3.5)), 2)
        out.append(_sig(
            "nlp.urgency",
            "language",
            "Urgency and deadline pressure",
            f"similarity={score:.2f}",
            w,
            RISK_MEDIUM,
            evidence=f"Zero-shot urgency similarity: {score:.2f}. Demands rapid action without deliberation.",
            detail={"similarity": round(score, 4)}
        ))

    # 2. Credential Harvesting
    if sims.get("credential", 0.0) >= 0.08:
        score = sims["credential"]
        w = round(min(1.90, max(0.50, score * 3.8)), 2)
        out.append(_sig(
            "nlp.credential_lure",
            "language",
            "Credential-harvesting language",
            f"similarity={score:.2f}",
            w,
            RISK_HIGH,
            evidence=f"Zero-shot credential similarity: {score:.2f}. Prompts for authentication/login recovery.",
            detail={"similarity": round(score, 4)}
        ))

    # 3. Payment & Financial Diversion
    if sims.get("financial", 0.0) >= 0.08:
        score = sims["financial"]
        w = round(min(1.90, max(0.50, score * 3.8)), 2)
        out.append(_sig(
            "nlp.payment_diversion",
            "language",
            "Payment-diversion language",
            f"similarity={score:.2f}",
            w,
            RISK_HIGH,
            evidence=f"Zero-shot financial intent similarity: {score:.2f}. Directs fund transfers or banking modifications.",
            detail={"similarity": round(score, 4)}
        ))

    # 4. Executive Authority Pressure
    if sims.get("authority", 0.0) >= 0.08:
        score = sims["authority"]
        w = round(min(1.80, max(0.50, score * 3.5)), 2)
        out.append(_sig(
            "nlp.authority_pressure",
            "language",
            "Executive authority combined with a request",
            f"similarity={score:.2f}",
            w,
            RISK_HIGH,
            evidence=f"Zero-shot authority similarity: {score:.2f}. Impersonates executive or leadership order.",
            detail={"similarity": round(score, 4)}
        ))

    # 5. Secrecy & Out-of-Band Process Bypass
    if sims.get("secrecy", 0.0) >= 0.08:
        score = sims["secrecy"]
        w = round(min(1.75, max(0.50, score * 3.5)), 2)
        out.append(_sig(
            "nlp.secrecy",
            "language",
            "Requests secrecy or bypassing process",
            f"similarity={score:.2f}",
            w,
            RISK_HIGH,
            evidence=f"Zero-shot secrecy similarity: {score:.2f}. Demands confidential out-of-channel compliance.",
            detail={"similarity": round(score, 4)}
        ))

    # 6. Weaponized Malware Execution Prompt
    if sims.get("malware", 0.0) >= 0.12:
        score = sims["malware"]
        w = round(min(1.90, max(0.60, score * 3.8)), 2)
        out.append(_sig(
            "nlp.malware_lure",
            "language",
            "Malware payload execution pretext",
            f"similarity={score:.2f}",
            w,
            RISK_HIGH,
            evidence=f"Zero-shot malware pretext similarity: {score:.2f}. Requests macro enabling or script execution.",
            detail={"similarity": round(score, 4)}
        ))

    return out


def check_language(parsed: ParsedEmail) -> List[Signal]:
    """Social-engineering language analysis using Zero-Shot TF-IDF Cosine Similarity."""
    body = (parsed.body_text or strip_html(parsed.body_html) or "").lower()
    subject = (parsed.subject or "").lower()
    out = extract_signals(subject, body)

    # Payload-free BEC flag
    has_financial = any(s.id == "nlp.payment_diversion" for s in out)
    if has_financial and not parsed.urls and not parsed.attachments:
        out.append(_sig(
            "nlp.bec_no_payload",
            "bec",
            "Financial request with no link or attachment",
            "text-only payment request",
            1.25,
            RISK_HIGH,
            evidence="Text-only BEC evades link and attachment scanners entirely."
        ))

    letters = [c for c in (parsed.subject or "") if c.isalpha()]
    if len(letters) >= 8:
        upper_ratio = sum(c.isupper() for c in letters) / len(letters)
        if upper_ratio > 0.6:
            out.append(_sig("nlp.shouting_subject",
                            "language",
                            "Subject is mostly upper case",
                            "%.0f%% caps" % (upper_ratio * 100),
                            0.55,
                            RISK_LOW,
                            evidence=parsed.subject[:120]))
    if parsed.body_html:
        hidden = re.findall(
            r"(?i)(?:font-size\s*:\s*0(?:\.0+)?(?:px|pt|em)?|color\s*:\s*#?fff(?:fff)?\b|display\s*:\s*none|visibility\s*:\s*hidden)",
            parsed.body_html)
        if hidden:
            out.append(
                _sig(
                    "nlp.hidden_text",
                    "obfuscation",
                    "Hidden text in HTML body",
                    "%d occurrence(s)" %
                    len(hidden),
                    1.15,
                    RISK_MEDIUM,
                    evidence="Invisible text is used to dilute keyword-based filters."))
        vis = strip_html(parsed.body_html)
        if len(parsed.body_html) > 400 and len(
                vis.strip()) < 40 and parsed.urls:
            out.append(
                _sig(
                    "nlp.image_only",
                    "obfuscation",
                    "Image-only body with links",
                    "little readable text",
                    0.95,
                    RISK_MEDIUM,
                    evidence="Rendering the lure as an image defeats text analysis."))
    if parsed.has_qr_code and not parsed.urls:
        out.append(
            _sig(
                "nlp.possible_quishing",
                "obfuscation",
                "Inline image with no links (possible QR lure)",
                "image present",
                0.90,
                RISK_MEDIUM,
                evidence="QR payload not decoded; flagged for manual inspection rather than guessed."))
    return out


def check_urls(parsed: ParsedEmail) -> List[Signal]:
    out: List[Signal] = []
    from_reg = registrable(parsed.from_domain)
    for i, u in enumerate(parsed.urls[:40]):
        if u.is_ip_literal:
            out.append(_sig("url.ip_literal.%d" % i,
                            "url",
                            "Link points at a bare IP address",
                            u.url[:200],
                            1.75,
                            RISK_HIGH,
                            evidence="Legitimate services publish hostnames."))
        if u.anchor_mismatch:
            out.append(_sig("url.anchor_mismatch.%d" % i, "url",
                            "Visible link text differs from the destination",
                            "%s -> %s" % (u.anchor_text[:60], u.domain), 1.85, RISK_HIGH,
                            evidence="The user sees one domain and is sent to another."))
        if u.is_punycode:
            out.append(
                _sig(
                    "url.punycode.%d" %
                    i,
                    "url",
                    "Punycode link domain",
                    u.domain,
                    1.60,
                    RISK_HIGH,
                    evidence="Decodes to a non-ASCII lookalike."))
        if u.is_shortener:
            out.append(_sig("url.shortener.%d" % i,
                            "url",
                            "URL shortener hides the destination",
                            u.domain,
                            0.85,
                            RISK_MEDIUM,
                            evidence=u.url[:200]))
        sk = skeleton(u.registrable_domain.split(
            ".")[0]) if u.registrable_domain else ""
        for brand in PROTECTED_BRANDS:
            if sk and 0 < levenshtein(sk, brand) <= max(1, len(brand) // 5):
                out.append(
                    _sig(
                        "url.lookalike.%d" %
                        i,
                        "url",
                        "Link domain is a lookalike of %s" %
                        brand,
                        u.domain,
                        2.20,
                        RISK_CRITICAL,
                        evidence="%s is one or two edits from %s." %
                        (u.registrable_domain,
                         brand)))
                break
        if "credential-collection path keyword" in u.reasons and u.registrable_domain != from_reg:
            out.append(_sig("url.credential_path.%d" % i,
                            "url",
                            "Login-style path on an unrelated domain",
                            u.url[:200],
                            1.35,
                            RISK_HIGH,
                            evidence="Path suggests a sign-in page hosted off-brand."))
        if u.tld in SUSPICIOUS_TLDS:
            out.append(_sig("url.bad_tld.%d" %
                            i, "url", "Link uses a high-abuse TLD", ".%s" %
                            u.tld, 0.80, RISK_MEDIUM, evidence=u.url[:200]))
    if len(parsed.urls) > 15:
        out.append(
            _sig(
                "url.many",
                "url",
                "Unusually high link count",
                "%d links" % len(
                    parsed.urls),
                0.45,
                RISK_LOW,
                evidence="Link stuffing is used to bury the malicious destination."))
    return out


def check_attachments(parsed: ParsedEmail) -> List[Signal]:
    out: List[Signal] = []
    for i, a in enumerate(parsed.attachments[:20]):
        if a.is_executable:
            out.append(_sig("att.executable.%d" % i,
                            "attachment",
                            "Executable attachment",
                            a.filename,
                            2.50,
                            RISK_CRITICAL,
                            evidence="Detected type %s, sha256 %s." % (a.detected_type,
                                                                       a.sha256[:16])))
        if a.double_extension:
            out.append(
                _sig(
                    "att.double_ext.%d" %
                    i,
                    "attachment",
                    "Double file extension",
                    a.filename,
                    2.10,
                    RISK_CRITICAL,
                    evidence="Windows hides the trailing known extension from the user."))
        if a.extension_mismatch:
            out.append(
                _sig(
                    "att.type_mismatch.%d" %
                    i,
                    "attachment",
                    "File content does not match its extension",
                    "%s is really %s" %
                    (a.filename,
                     a.detected_type),
                    1.80,
                    RISK_HIGH,
                    evidence="Magic-byte inspection disagrees with the declared type."))
        if a.is_macro_capable:
            out.append(
                _sig(
                    "att.macro.%d" %
                    i,
                    "attachment",
                    "Macro-capable Office document",
                    a.filename,
                    1.40,
                    RISK_MEDIUM,
                    evidence="Legacy Office formats can carry VBA macros."))
        if a.is_archive:
            out.append(
                _sig(
                    "att.archive.%d" %
                    i,
                    "attachment",
                    "Archive attachment",
                    a.filename,
                    0.70,
                    RISK_LOW,
                    evidence="Archives are used to wrap payloads past content scanners."))
    return out


def check_headers(parsed: ParsedEmail) -> List[Signal]:
    out: List[Signal] = []
    if not parsed.message_id:
        out.append(
            _sig(
                "hdr.no_message_id",
                "header",
                "Missing Message-ID",
                "absent",
                0.90,
                RISK_MEDIUM,
                evidence="Standards-compliant MTAs always set one."))
    elif parsed.from_domain:
        mid_dom = parsed.message_id.strip("<>").rsplit("@", 1)[-1].lower()
        if mid_dom and registrable(mid_dom) != registrable(parsed.from_domain):
            out.append(
                _sig(
                    "hdr.message_id_mismatch",
                    "header",
                    "Message-ID domain differs from sender domain",
                    mid_dom,
                    0.75,
                    RISK_LOW,
                    evidence="Common when mail is injected by a bulk sending tool."))
    if not parsed.received_chain:
        out.append(
            _sig(
                "hdr.no_received",
                "header",
                "No Received headers",
                "chain absent",
                1.30,
                RISK_MEDIUM,
                evidence="Relay path cannot be reconstructed; the message may have been injected directly."))
    if not parsed.to and not parsed.cc:
        out.append(
            _sig(
                "hdr.undisclosed_recipients",
                "header",
                "No visible recipients",
                "To and Cc empty",
                0.70,
                RISK_LOW,
                evidence="Bcc-only delivery is normal for bulk mail and common in phishing runs."))
    if len(parsed.to) + len(parsed.cc) > 20:
        out.append(_sig("hdr.mass_recipients", "header", "Large recipient list",
                        "%d recipients" % (len(parsed.to) + len(parsed.cc)), 0.55, RISK_LOW,
                        evidence="Indicates a campaign rather than a targeted message."))
    xmailer = parsed.x_headers.get(
        "x-mailer",
        "") or parsed.x_headers.get(
        "X-Mailer",
        "")
    if re.search(r"(?i)(phpmailer|sendmail-php|mass|bulk|smtplib)", xmailer):
        out.append(_sig("hdr.bulk_mailer",
                        "header",
                        "Sent by a scripted mailer",
                        xmailer[:80],
                        1.05,
                        RISK_MEDIUM,
                        evidence="X-Mailer indicates a script, not a mail client."))
    return out


def check_relay(hops: List[RelayHop]) -> List[Signal]:
    """Routing anomalies. Only called once the relay path is built."""
    out: List[Signal] = []
    for h in hops:
        if not h.anomaly_reasons:
            continue
        # One signal per hop, not one per reason. Emitting a signal per reason
        # produced duplicate ids *and* counted the same hop several times in the
        # log-odds sum, so a single oddly-named relay could outweigh a DMARC
        # failure. Extra reasons on the same hop add sub-linearly instead: the
        # second observation about one host is corroboration, not a new host.
        n = len(h.anomaly_reasons)
        weight = round(min(1.15 + 0.25 * (n - 1), 1.90), 3)
        out.append(
            _sig(
                "relay.anomaly.%d" %
                h.index,
                "relay",
                "Relay anomaly at hop %d" %
                h.index,
                "; ".join(
                    h.anomaly_reasons),
                weight,
                RISK_MEDIUM,
                "relay",
                evidence="%s (%s)" %
                (h.ip or "unknown ip",
                 h.location.country or "location unresolved"),
                detail={
                    "hop": h.index,
                    "ip": h.ip,
                    "asn": h.location.asn,
                    "reasons": h.anomaly_reasons,
                    "reason_count": n},
            ))
    public = [h for h in hops if not h.is_private]
    countries = [
        h.location.country_code for h in public if h.location.country_code]
    if len(set(countries)) >= 3:
        out.append(
            _sig(
                "relay.multi_country",
                "relay",
                "Message crossed three or more countries",
                " -> ".join(
                    dict.fromkeys(countries)),
                0.80,
                RISK_MEDIUM,
                "relay",
                evidence="Long international relay chains are typical of abused infrastructure."))
    return out


def ml_signal(pred: MlPrediction) -> Optional[Signal]:
    """Convert the classifier probability into a log-odds contribution.

    The model's own logit is the natural unit here, but we damp it (0.6) and clamp
    it to +/-2.2 so a single overconfident model cannot dominate the rule
    evidence. That damping is the honest reflection of a model trained on a
    small corpus.
    """
    if not pred.available or pred.probability is None:
        return None
    p = min(max(pred.probability, 1e-4), 1 - 1e-4)
    logit = math.log(p / (1 - p))
    weight = max(-2.2, min(2.2, 0.6 * logit))
    sev = RISK_HIGH if p >= 0.8 else RISK_MEDIUM if p >= 0.5 else RISK_CLEAN
    tops = ", ".join("%s(%+.2f)" % (f.feature, f.contribution)
                     for f in pred.top_features[:5])
    return _sig(
        "ml.score",
        "ml_score",
        "ML classifier score",
        "%.1f%% phishing" %
        (p *
         100),
        weight,
        sev,
        "ml",
        evidence="Model %s. Top contributions: %s" %
        (pred.model_name,
         tops or "n/a"),
        detail={
            "probability": p,
            "model": pred.model_name})


def run_rules(parsed: ParsedEmail) -> List[Signal]:
    """All deterministic checks. Relay and ML signals are added later."""
    signals: List[Signal] = []
    signals += check_authentication(parsed)
    signals += check_identity(parsed)
    signals += check_language(parsed)
    signals += check_urls(parsed)
    signals += check_attachments(parsed)
    signals += check_headers(parsed)
    return signals


def logistic(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def dedupe_signals(signals: List[Signal]) -> List[Signal]:
    """Keep one signal per id, the heaviest one.

    Evidence is combined by *summing* log-odds, so the same signal appearing twice
    silently doubles its influence. That is a real scoring bug rather than an
    aesthetic one - it happened once when a per-hop check emitted one signal per
    reason - so the guard lives here, in front of the scorer, where every caller
    passes through it.
    """
    best: Dict[str, Signal] = {}
    for s in signals:
        prior = best.get(s.id)
        if prior is None or abs(s.weight) > abs(prior.weight):
            best[s.id] = s
    if len(best) != len(signals):
        log.debug("dropped %d duplicate signal(s)", len(signals) - len(best))
    return [s for s in signals if best.get(s.id) is s]


def score(signals: List[Signal]) -> Tuple[float, Dict[str, float]]:
    """Combine signal weights in log-odds space. Returns (0-100, breakdown)."""
    logit = PRIOR_LOGIT
    breakdown: Dict[str, float] = {"prior": PRIOR_LOGIT}
    for s in dedupe_signals(signals):
        if not s.triggered:
            continue
        logit += s.weight
        breakdown[s.category] = round(
            breakdown.get(s.category, 0.0) + s.weight, 4)
    breakdown["total_logit"] = round(logit, 4)
    # Clamped to [0.1, 99.9]: the logistic saturates long before the evidence is
    # actually conclusive, and a forensic tool should never print "0" or "100"
    # certainty on a probabilistic score.
    return round(min(99.9, max(0.1, logistic(logit) * 100.0)), 1), breakdown


def risk_level(risk: float) -> str:
    if risk >= 85:
        return RISK_CRITICAL
    if risk >= 65:
        return RISK_HIGH
    if risk >= 40:
        return RISK_MEDIUM
    if risk >= 15:
        return RISK_LOW
    return RISK_CLEAN


def confidence(signals: List[Signal], pred: MlPrediction, risk: float,
               coverage: float) -> Tuple[float, List[str]]:
    """How much the verdict should be trusted, as a separate number.

    Three independent factors, combined as a weighted geometric mean so that a
    single bad factor drags the result down (an arithmetic mean would let strong
    coverage hide total rule/model disagreement):

      decisiveness = |risk - 50| / 50          distance from the boundary
      agreement    = 1 - |p_rules - p_model|   do the two views concur
      coverage     = checks that returned usable data / checks attempted

      confidence = 100 * decisiveness^0.45 * agreement^0.35 * coverage^0.20
    """
    flags: List[str] = []
    decisive = abs(risk - 50.0) / 50.0
    if decisive < 0.2:
        flags.append("score sits close to the decision boundary")

    if pred.available and pred.probability is not None:
        agreement = 1.0 - abs((risk / 100.0) - pred.probability)
        if agreement < 0.6:
            flags.append("rule engine and ML model disagree materially")
    else:
        agreement = 0.62
        flags.append("no ML model available, rules only")

    if coverage < 0.7:
        flags.append("some enrichment checks were unavailable")

    strong = [
        s for s in signals if s.triggered and s.severity in {
            RISK_HIGH,
            RISK_CRITICAL}]
    if risk >= 50 and not strong:
        flags.append("verdict rests on weak signals only")
    # A clean, well-authenticated message that still scores mid-range is the
    # AI-generated-phishing case: nothing technical to point at, tone alone.
    lang_only = all(s.category == "heuristic" and s.signal_type == "language"
                    for s in signals if s.triggered and s.weight > 0)
    if 35 <= risk <= 70 and lang_only:
        flags.append(
            "only language signals fired; possible AI-generated content")

    eps = 1e-6
    conf = 100.0 * (max(decisive, eps) ** 0.45) * \
        (max(agreement, eps) ** 0.35) * (max(coverage, eps) ** 0.20)
    conf = round(max(1.0, min(99.0, conf)), 1)
    if flags:
        conf = round(conf * (0.9 ** len(flags)), 1)
    return conf, flags


CLASS_TO_VERDICT = {
    0: "benign",
    1: "suspicious",
    2: "phishing",
    3: "bec",
    4: "malware",
}

CLASS_TO_BASE_RISK = {
    0: (1.0, 18.0),    # benign: 1-18 (negligible baseline)
    1: (28.0, 52.0),   # suspicious: 28-52 (moderate anomaly/spam)
    2: (58.0, 78.0),   # phishing: 58-78 (credential theft/fake link)
    3: (74.0, 89.0),   # bec: 74-89 (high-dollar wire fraud)
    4: (80.0, 95.0),   # malware: 80-95 (weaponized payload execution)
}


def calculate_risk_score(
    ml_class: int,
    ml_prob: float,
    signal_count: int = 0,
    spearphish_score: float = 0.0,
    signals: Optional[List[Signal]] = None,
) -> Tuple[float, str]:
    verdict = CLASS_TO_VERDICT.get(ml_class, "suspicious")
    base_min, base_max = CLASS_TO_BASE_RISK.get(ml_class, (28.0, 52.0))
    if ml_class == 0:
        mal_prob = max(0.0, 1.0 - ml_prob)
        risk = base_min + (base_max - base_min) * (mal_prob ** 1.5)
    else:
        # Scale smoothly across the band
        p_factor = min(1.0, max(0.0, ml_prob)) ** 0.85
        risk = base_min + (base_max - base_min) * p_factor

        # Add severity-weighted bonus
        if signals:
            crit = sum(1 for s in signals if s.triggered and s.severity == RISK_CRITICAL)
            high = sum(1 for s in signals if s.triggered and s.severity == RISK_HIGH)
            med = sum(1 for s in signals if s.triggered and s.severity == RISK_MEDIUM)
            sig_bonus = min(8.0, crit * 2.0 + high * 1.0 + med * 0.4)
        else:
            sig_bonus = min(6.0, signal_count * 0.8)
        risk += sig_bonus

        if spearphish_score > 0:
            risk = min(94.0, risk + spearphish_score * 4.5)

    return round(min(97.5, max(0.5, risk)), 1), verdict



def band(conf: float) -> str:
    return "high" if conf >= 70 else "moderate" if conf >= 40 else "low"


def build_verdict(
        signals: List[Signal],
        pred: MlPrediction,
        coverage: float) -> Verdict:
    signals = dedupe_signals(signals)
    rule_risk, breakdown = score(signals)
    conf, flags = confidence(signals, pred, rule_risk, coverage)

    # Determine verdict and risk score aligned with predicted class
    if pred.available and pred.predicted_class is not None:
        trig_signals = [s for s in signals if s.triggered and s.weight > 0]
        spear_score = 1.0 if any(s.id == "ml.spearphish_override" for s in signals) else 0.0
        c_name = CLASS_TO_VERDICT.get(pred.predicted_class, "benign")
        ml_p = float(pred.probabilities.get(c_name, pred.probability or 0.5)) if pred.probabilities else (pred.probability or 0.5)
        risk, label = calculate_risk_score(
            ml_class=pred.predicted_class,
            ml_prob=ml_p,
            signal_count=len(trig_signals),
            spearphish_score=spear_score,
            signals=trig_signals,
        )

    else:
        risk = rule_risk
        if risk >= 80:
            label = VERDICT_PHISHING
        elif risk >= 45:
            label = VERDICT_SUSPICIOUS
        elif risk >= 20:
            label = VERDICT_LIKELY_BENIGN
        else:
            label = VERDICT_BENIGN

    level = risk_level(risk)

    if conf < 35 and 20 <= risk <= 80:
        label = VERDICT_INDETERMINATE

    if label in (VERDICT_PHISHING, "phishing"):
        action = "Quarantine the message estate-wide, block sender and link domains, force password reset for anyone who clicked"
    elif label in (VERDICT_BEC, "bec"):
        action = "Freeze pending wire transfers, verify payment instructions out-of-band with executive, alert finance team"
    elif label in (VERDICT_MALWARE, "malware"):
        action = "Quarantine attachment estate-wide, isolate host, extract IoCs for EDR hunting"
    elif label in (VERDICT_SUSPICIOUS, "suspicious"):
        action = "Quarantine pending analyst confirmation and warn recipients"
    elif label in (VERDICT_INDETERMINATE, "indeterminate"):
        action = "Hold for manual review: automated confidence is too low to act on"
    elif label in (VERDICT_LIKELY_BENIGN, "likely_benign"):
        action = "Release with a soft warning banner"
    else:
        action = "Release to the recipient"

    top = sorted([s for s in signals if s.triggered and s.weight > 0],
                 key=lambda s: -s.weight)[:3]
    rationale = "; ".join("%s (%+.2f logit)" % (s.title, s.weight)
                          for s in top) or "no positive signals fired"
    return Verdict(
        label=label, risk_score=risk, risk_level=level, confidence=conf,
        confidence_band=band(conf), ambiguity_flags=flags,
        recommended_action=action,
        requires_human_review=(label not in (VERDICT_BENIGN, "benign") or conf < 70),
        rationale=rationale, score_breakdown=breakdown,
    )

