"""Case narrative: a paragraph an analyst can paste into a ticket.

Two producers, and the case records which one ran:

* **template** (default) - deterministic prose assembled from the evidence. No
  key, no network, identical every run, and it cannot hallucinate because it only
  interpolates values that exist on the case.
* **llm** - Anthropic's API, used only to *rewrite* the template's facts into
  smoother prose. The prompt passes the extracted evidence, not the raw email, and
  forbids new claims; if the model output drops the verdict or the risk score, the
  template version is used instead. Narrative source is surfaced in the UI and the
  PDF either way.

The reason for that guard: a forensic report's narrative is read as a finding. A
fluent sentence that invents a detail is worse than a stiff sentence that does
not, so the LLM is a stylist here and never a source of fact.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from ..config import get_settings
from ..privacy.redact import mask_text
from ..schemas import Case

log = logging.getLogger(__name__)

MAX_TOKENS = 700


def _facts(case: Case) -> Dict[str, Any]:
    """The evidence the narrative is allowed to mention. Nothing else is passed to
    a model, which also keeps message content out of a third-party API."""
    p, v = case.parsed_email, case.verdict
    top = [s for s in case.signals if s.triggered and s.weight > 0]
    top.sort(key=lambda s: -s.weight)
    return {
        "case_number": case.case_number,
        "verdict": v.label, "threat_class": v.threat_class,
        "risk_score": round(v.risk_score, 1), "risk_level": v.risk_level,
        "confidence": round(v.confidence, 1), "confidence_band": v.confidence_band,
        "ambiguity_flags": v.ambiguity_flags,
        "from_display": p.from_name, "from_domain": p.from_domain,
        "subject": p.subject[:160],
        "auth": {"spf": p.auth.spf, "dkim": p.auth.dkim, "dmarc": p.auth.dmarc,
                 "spf_aligned": p.auth.spf_aligned, "dkim_aligned": p.auth.dkim_aligned},
        "origin": {k: case.origin.get(k) for k in ("place", "precision", "confidence", "ip")},
        "hops": len(case.relay_hops),
        "top_signals": [{"title": s.title, "weight": round(s.weight, 2),
                         "result": s.result[:120]} for s in top[:6]],
        "ml": {"available": case.ml.available, "probability": case.ml.probability,
               "top_features": [f.feature for f in case.ml.top_features[:4]]},
        "attribution": {"actor_type": case.attribution.actor_type,
                        "confidence": case.attribution.confidence,
                        "reasons": case.attribution.reasons[:3]},
        "techniques": [m.get("technique") for m in case.mitre[:5]],
        "exposure": {"recipients": case.blast_radius.total_recipients,
                     "clicked": case.blast_radius.total_clicked,
                     "credentials": case.blast_radius.total_credentials_submitted},
        "campaign": {"id": case.campaign.id, "messages": case.campaign.case_count},
        "recommended_action": v.recommended_action,
    }


def template_narrative(case: Case) -> str:
    """Deterministic narrative. This is the reference text the LLM must not contradict."""
    f = _facts(case)
    p = case.parsed_email
    auth = f["auth"]
    parts: List[str] = []

    parts.append(
        "Case %s concerns a message from %s <%s> with the subject %r, assessed as %s "
        "(%s) with a risk score of %.1f/100 at %.0f%% confidence." %
        (f["case_number"],
         p.from_name or "no display name",
         p.from_address or "unknown sender",
         f["subject"],
            f["verdict"],
            f["threat_class"],
            f["risk_score"],
            f["confidence"]))

    auth_line = ("SPF %s, DKIM %s, DMARC %s"
                 % (auth["spf"] or "absent", auth["dkim"] or "absent",
                    auth["dmarc"] or "absent"))
    if auth["spf"] == "pass" and not auth["spf_aligned"]:
        auth_line += (". SPF passed for the envelope sender but does not align with the "
                      "From domain, which is the signature of a spoofed display identity "
                      "sent through infrastructure the attacker legitimately controls")
    elif auth["spf_aligned"] or auth["dkim_aligned"]:
        auth_line += ". At least one identifier aligns with the From domain"
    parts.append("Authentication: %s." % auth_line)

    origin = f["origin"]
    if origin.get("ip"):
        parts.append(
            "The Received chain contains %d hop(s); the earliest reliable sending node is "
            "%s, geolocated to %s at %s precision (%s confidence in the origin claim)." %
            (f["hops"],
             origin["ip"],
                origin.get("place") or "an unresolved location",
                origin.get("precision"),
                origin.get("confidence")))
    else:
        parts.append(
            "No routable sending node could be established from the Received chain, "
            "so the origin is not asserted.")

    if f["top_signals"]:
        parts.append("The strongest evidence was: %s."
                     % "; ".join("%s (%s)" % (s["title"], s["result"])
                                 for s in f["top_signals"][:4]))
    ml = f["ml"]
    if ml["available"] and ml["probability"] is not None:
        parts.append(
            "The trained classifier independently scored the content at %.2f "
            "probability of phishing, driven by %s." %
            (ml["probability"], ", ".join(
                ml["top_features"]) or "no single feature"))
    att = f["attribution"]
    if att["actor_type"]:
        parts.append(
            "Attribution: the evidence best supports %s at %.0f%% confidence%s. "
            "This describes the mechanism of the send, not the identity of a person." %
            (att["actor_type"], att["confidence"], " (%s)" %
             att["reasons"][0] if att["reasons"] else ""))
    if f["techniques"]:
        parts.append(
            "Mapped ATT&CK techniques: %s." %
            ", ".join(
                t for t in f["techniques"] if t))
    exp = f["exposure"]
    if exp["recipients"]:
        parts.append(
            "Exposure: %d recipient(s) received the wave, %d clicked and %d submitted "
            "credentials." %
            (exp["recipients"], exp["clicked"], exp["credentials"]))
    if f["ambiguity_flags"]:
        parts.append("Confidence is reduced because %s." %
                     "; ".join(f["ambiguity_flags"][:3]))
    parts.append("Recommended action: %s." % f["recommended_action"])
    return " ".join(parts)


def _llm_narrative(case: Case, reference: str) -> Optional[str]:
    """Ask Anthropic to rewrite ``reference``. Returns None on any doubt."""
    st = get_settings()
    if not (st.has_llm and st.allow_network):
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        log.info("anthropic sdk not installed; using template narrative")
        return None
    facts = _facts(case)
    prompt = (
        "You are writing the summary paragraph of an email forensic report for a SOC "
        "analyst. Rewrite the reference summary below so it reads as clear professional "
        "prose.\n\n"
        "Hard rules:\n"
        "- Use ONLY facts present in the JSON evidence and the reference summary.\n"
        "- Do not add attribution to any person, company, or country beyond what is given.\n"
        "- Keep the verdict, the risk score and the confidence exactly as given.\n"
        "- Do not speculate about intent beyond the stated classification.\n"
        "- 120-200 words, no bullet points, no headings.\n\n"
        "EVIDENCE JSON:\n%s\n\nREFERENCE SUMMARY:\n%s\n" %
        (json.dumps(facts, indent=1, default=str), reference))
    try:
        client = anthropic.Anthropic(api_key=st.anthropic_api_key)
        msg = client.messages.create(
            model=st.anthropic_model, max_tokens=MAX_TOKENS, temperature=0.2,
            messages=[{"role": "user", "content": prompt}])
        text = "".join(getattr(block, "text", "")
                       for block in msg.content).strip()
    except Exception as exc:  # noqa: BLE001 - any API problem falls back silently
        log.warning("LLM narrative failed: %s", str(exc)[:140])
        return None
    if not _narrative_is_faithful(text, case):
        log.warning(
            "LLM narrative dropped or altered a required fact; using template")
        return None
    return text


def _narrative_is_faithful(text: str, case: Case) -> bool:
    """Cheap fidelity check: the model must keep the verdict and the score.

    Not a full entailment check - that is not possible here - but it catches the
    two failure modes that would actually mislead a reader: a changed verdict and
    a changed number.
    """
    if len(text) < 200 or len(text) > 3000:
        return False
    low = text.lower()
    if case.verdict.label.replace(
            "_", " ") not in low and case.verdict.label not in low:
        return False
    score = "%.1f" % case.verdict.risk_score
    return score in text or str(int(round(case.verdict.risk_score))) in text


def build_narrative(case: Case) -> Tuple[str, str]:
    """Return ``(narrative, source)`` where source is ``template`` or ``llm``."""
    reference = template_narrative(case)
    live = _llm_narrative(case, reference)
    if live:
        return mask_text(live) if get_settings().pii_masking else live, "llm"
    return mask_text(reference) if get_settings(
    ).pii_masking else reference, "template"


def attach_narrative(case: Case) -> Case:
    text, source = build_narrative(case)
    case.verdict.narrative = text
    case.verdict.narrative_source = source
    return case
