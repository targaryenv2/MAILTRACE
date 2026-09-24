"""Identity correlation, campaign clustering and confidence-based attribution.

PS-26106 asks for two things this module owns:

1. **Graph-based relationship analysis** - link cases through the artefacts they
   share (sender address, registrable domain, relay IP, ASN, link host,
   attachment digest) and expose the resulting cluster, so an analyst sees "this
   is the eleventh message from the same infrastructure" instead of eleven
   unrelated tickets.
2. **Confidence-based attribution** distinguishing a *compromised account* from a
   *spoofed domain* from *anonymised infrastructure* from a *direct actor*.

The distinction in (2) is operationally load-bearing, not cosmetic. Each one
implies a different response: reset the credential, enforce DMARC, block the
egress range, or preserve evidence for referral. Getting it wrong wastes the
response window, so attribution here is a *ranked hypothesis with reasons and a
confidence*, never a bare assertion, and every alternative that the evidence
also supports is listed alongside.

Attribution logic, in short:

* authentication **passes and aligns** for a real, aged domain, but the content
  is a payment/credential ask -> the account itself is probably compromised;
* authentication **fails or is unaligned** while the From domain is a real brand
  -> the domain is being spoofed by someone who does not control it;
* the origin hop is Tor / a VPN / an open relay / bulletproof hosting, or the
  chain is manipulated -> the actor is hiding behind anonymised infrastructure
  and header attribution stops at the proxy;
* the origin hop resolves to ordinary hosting with consistent rDNS and the
  sender domain was registered days ago by the same party -> direct actor.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..schemas import (
    ACTOR_ANONYMISED,
    ACTOR_COMPROMISED,
    ACTOR_DIRECT,
    ACTOR_UNKNOWN,
    ACTOR_SPOOFED,
    Attribution,
    Case,
    GraphEdge,
    GraphNode,
    Ioc,
    SOURCE_COMPUTED,
)

log = logging.getLogger(__name__)

# Indicator families that mean "the trail ends here", taken from the geoip
# classifier's vocabulary.
ANON_MARKERS = ("tor", "vpn", "proxy", "open relay", "open-relay", "anonymis",
                "anonymiz", "bulletproof")
HOSTING_MARKERS = (
    "hosting",
    "cloud",
    "data center",
    "datacenter",
    "colo",
    "vps")
BOTNET_MARKERS = (
    "dynamic",
    "residential",
    "botnet",
    "cpe",
    "dsl",
    "broadband")

_WS = re.compile(r"\s+")
_NUM = re.compile(r"\d+")


def _norm_subject(subject: str) -> str:
    """Strip the parts of a subject an attacker varies per victim: reply/forward
    prefixes, invoice numbers, amounts and the victim's own name are all noise
    when deciding whether two mails belong to one campaign."""
    text = (subject or "").lower()
    text = re.sub(r"^\s*(re|fw|fwd|aw|sv)\s*:\s*", "", text)
    text = _NUM.sub("#", text)
    return _WS.sub(" ", re.sub(r"[^a-z#\s]", " ", text)).strip()


def _hash(*parts: str) -> str:
    return hashlib.sha256(
        "|".join(p for p in parts if p).encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# artefacts
# ---------------------------------------------------------------------------


def case_artefacts(case: Case) -> Dict[str, List[str]]:
    """The identity-bearing artefacts of one case, normalised for comparison.

    Kept as a dict of lists (not a set) so the graph builder can label edges with
    *which* artefact family matched - "shares a relay IP" and "shares a subject
    shape" are very different strengths of evidence.
    """
    p = case.parsed_email
    from_addr = (p.from_address or case.sender_address or "").lower()
    from_dom = (p.from_domain or from_addr.rpartition("@")[2]).lower()
    reply_to = (p.reply_to or "").lower()
    ips = [h.ip for h in case.relay_hops if h.ip and not h.is_private]
    asns = [h.location.asn for h in case.relay_hops
            if h.location and h.location.asn]
    hosts = []
    for u in p.urls:
        dom = (u.registrable_domain or u.domain or "").lower()
        if dom:
            hosts.append(dom)
    return {
        "sender": [from_addr] if from_addr else [],
        "domain": sorted({d for d in [from_dom,
                                      reply_to.rpartition("@")[2],
                                      (p.return_path or "").rpartition("@")[2].lower()] if d}),
        "ip": sorted(set(ips)),
        "asn": sorted({a for a in asns}),
        "url_host": sorted(set(hosts)),
        "attachment": sorted({a.sha256 for a in p.attachments if a.sha256}),
        "subject_shape": [_norm_subject(p.subject or case.subject)],
    }


def fingerprint(case: Case) -> str:
    """Campaign fingerprint for a case.

    Delegates to :func:`ingestion.parser.fingerprint` on purpose: two fingerprint
    definitions would eventually disagree, and then the campaign count in the
    queue and the wave lookup in the blast-radius module would silently describe
    different groupings. There is exactly one definition, and it lives with the
    parser because it depends only on parsed fields.
    """
    from ..ingestion.parser import fingerprint as parsed_fingerprint
    return parsed_fingerprint(case.parsed_email)


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------

# Shared-artefact weights: how much each family of overlap contributes to the
# claim that two cases are the same campaign. An attachment digest is near-proof;
# a shared ASN is weak on its own because whole clouds share one.
LINK_WEIGHTS = {
    "attachment": 1.00, "sender": 0.85, "url_host": 0.75, "ip": 0.70,
    "domain": 0.60, "subject_shape": 0.40, "asn": 0.20,
}
LINK_THRESHOLD = 0.80  # sum of weights required to call two cases related


def relate(a: Case, b: Case) -> Tuple[float, List[str]]:
    """Score the relationship between two cases and say what matched."""
    art_a, art_b = case_artefacts(a), case_artefacts(b)
    score = 0.0
    matched: List[str] = []
    for kind, weight in LINK_WEIGHTS.items():
        shared = sorted(set(art_a.get(kind, [])) & set(art_b.get(kind, [])))
        shared = [s for s in shared if s]
        if not shared:
            continue
        score += weight
        matched.append("%s=%s" % (kind, ",".join(shared[:3])))
    return round(score, 3), matched


def correlate_cases(case: Case, others: Sequence[Case],
                    threshold: float = LINK_THRESHOLD) -> Dict[str, Any]:
    """Find the cases related to ``case`` and describe the cluster.

    Cluster id is derived from the sorted case ids so it is stable and needs no
    counter in the database; two runs over the same set produce the same id.
    """
    related: List[Dict[str, Any]] = []
    for other in others:
        if other.id == case.id:
            continue
        score, matched = relate(case, other)
        if score >= threshold:
            related.append({"case_id": other.id,
                            "case_number": other.case_number,
                            "score": score,
                            "matched": matched,
                            "subject": other.subject[:120],
                            "verdict": other.verdict.label,
                            "created_at": other.created_at})
    related.sort(key=lambda r: (-r["score"], r["created_at"]))
    ids = sorted([case.id] + [r["case_id"] for r in related])
    shared: List[str] = []
    for r in related:
        for m in r["matched"]:
            if m not in shared:
                shared.append(m)
    return {
        "cluster_id": "cl-%s" % _hash(*ids) if related else "",
        "cluster_size": len(ids),
        "related": related,
        "shared_indicators": shared[:12],
        "fingerprint": fingerprint(case),
    }


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


def build_graph(case: Case, related: Optional[Sequence[Case]] = None
                ) -> Tuple[List[GraphNode], List[GraphEdge]]:
    """Build the node/edge set the investigator screen renders.

    The graph is centred on the case rather than being a global graph: a global
    view is unreadable past a few dozen cases, and the question an analyst is
    actually asking is "what else touches *this* one".
    """
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    def node(nid: str, kind: str, label: str, risk: float = 0.0,
             detail: Optional[Dict[str, Any]] = None) -> str:
        if nid in nodes:
            nodes[nid].weight += 1
        else:
            nodes[nid] = GraphNode(id=nid,
                                   kind=kind,
                                   label=label[:80],
                                   risk=risk,
                                   detail=detail or {})
        return nid

    def edge(src: str, dst: str, kind: str, weight: float = 1.0) -> None:
        if src and dst and src != dst:
            edges.append(
                GraphEdge(
                    source=src,
                    target=dst,
                    kind=kind,
                    weight=weight))

    def add_case(c: Case, is_focus: bool) -> None:
        cid = node("case:%s" % c.id, "case", c.case_number or c.id,
                   risk=c.verdict.risk_score,
                   detail={"focus": is_focus, "verdict": c.verdict.label,
                           "subject": c.subject[:100]})
        art = case_artefacts(c)
        for addr in art["sender"]:
            edge(
                cid,
                node(
                    "sender:%s" %
                    addr,
                    "sender",
                    addr,
                    risk=c.verdict.risk_score),
                "sent-by")
        for dom in art["domain"]:
            edge(
                cid,
                node(
                    "domain:%s" %
                    dom,
                    "domain",
                    dom),
                "uses-domain",
                0.8)
        for ip in art["ip"]:
            hop = next((h for h in c.relay_hops if h.ip == ip), None)
            place = ""
            if hop is not None and hop.location and hop.location.country:
                place = hop.location.country
            nid = node(
                "ip:%s" %
                ip, "ip", ip, detail={
                    "country": place, "anomalous": bool(
                        hop and hop.is_anomalous)})
            edge(cid, nid, "relayed-via", 0.7)
            if hop is not None and hop.location and hop.location.asn:
                edge(
                    nid,
                    node(
                        "asn:%s" %
                        hop.location.asn,
                        "asn",
                        hop.location.isp or hop.location.asn),
                    "shares-asn",
                    0.2)
        for host in art["url_host"]:
            edge(cid, node("url:%s" % host, "url", host), "links-to", 0.75)
        for digest in art["attachment"]:
            edge(cid, node("file:%s" % digest, "attachment", digest[:16]),
                 "same-attachment", 1.0)
        if c.recipient:
            edge(
                node(
                    "recipient:%s" %
                    c.recipient.lower(),
                    "recipient",
                    c.recipient),
                cid,
                "received",
                0.3)

    add_case(case, True)
    for other in related or ():
        add_case(other, False)
    return list(nodes.values()), edges


# ---------------------------------------------------------------------------
# attribution
# ---------------------------------------------------------------------------


def _signal_ids(case: Case) -> set:
    return {s.id.rsplit(".", 1)[0] if s.id[-1].isdigit() else s.id
            for s in case.signals if s.triggered}


def _band(value: float) -> str:
    return "high" if value >= 70 else "moderate" if value >= 40 else "low"


def attribute(case: Case, correlation: Optional[Dict[str, Any]] = None,
              domain_age_days: Optional[int] = None) -> Attribution:
    """Rank the attribution hypotheses for one case.

    Confidence is the share of the winning hypothesis' evidence over the total
    evidence across all hypotheses, scaled by how much evidence there is at all -
    so one weak indicator yields low confidence even when it is unopposed, which
    is the behaviour an evidence log needs.
    """
    auth = case.parsed_email.auth
    ids = _signal_ids(case)
    origin = case.origin or {}
    indicators = [str(i) for i in origin.get("indicators", [])]
    ind_text = " ".join(indicators).lower()
    hop_hosts = " ".join((h.hostname or "") for h in case.relay_hops).lower()
    anomalies = [r for h in case.relay_hops for r in (h.anomaly_reasons or [])]

    scores: Dict[str, float] = {k: 0.0 for k in (
        ACTOR_COMPROMISED, ACTOR_SPOOFED, ACTOR_ANONYMISED, ACTOR_DIRECT)}
    why: Dict[str, List[str]] = {k: [] for k in scores}

    def add(actor: str, weight: float, reason: str) -> None:
        scores[actor] += weight
        why[actor].append(reason)

    # -- anonymised infrastructure -----------------------------------------
    if any(m in ind_text or m in hop_hosts for m in ANON_MARKERS):
        add(ACTOR_ANONYMISED, 3.0,
            "origin hop is consistent with anonymising infrastructure (%s)"
            % (", ".join(i for i in indicators if any(m in i.lower() for m in ANON_MARKERS))
               or "hostname pattern"))
    if "intel.tor_exit" in ids:
        add(ACTOR_ANONYMISED, 2.0,
            "threat intelligence reports the origin IP as a Tor exit")
    if any("manipulat" in a.lower() or "forged" in a.lower()
           for a in anomalies):
        add(ACTOR_ANONYMISED, 1.5, "Received chain shows signs of manipulation: %s"
            % "; ".join(sorted({a for a in anomalies})[:2]))
    if origin.get("precision") in ("unknown", "") and case.relay_hops:
        add(ACTOR_ANONYMISED, 0.5, "earliest reliable hop could not be geolocated")

    # -- spoofed domain ----------------------------------------------------
    spoof_ids = {"auth.spf_fail", "auth.dkim_fail", "auth.dmarc_fail",
                 "auth.spf_unaligned", "id.returnpath_mismatch"}
    hit = sorted(spoof_ids & ids)
    if hit:
        add(ACTOR_SPOOFED, 1.2 *
            len(hit), "sender authentication does not support the From domain (%s)" %
            ", ".join(hit))
    if "id.brand_impersonation" in ids and not (domain_age_days or 0):
        add(ACTOR_SPOOFED, 1.0, "From header claims a protected brand")
    if "auth.no_auth" in ids:
        add(ACTOR_SPOOFED, 0.8, "message carries no authentication results at all")

    # -- compromised account ----------------------------------------------
    aligned = bool(auth.spf_aligned or auth.dkim_aligned)
    dmarc_ok = (auth.dmarc or "").lower() == "pass"
    if aligned and dmarc_ok:
        social = {
            "nlp.payment_diversion",
            "nlp.bec_no_payload",
            "nlp.credential_lure",
            "nlp.authority_pressure",
            "nlp.secrecy"} & ids
        if social:
            add(ACTOR_COMPROMISED, 3.0,
                "authentication passes and aligns for the From domain, yet the content is a "
                "social-engineering ask (%s) - consistent with a legitimate mailbox in "
                "attacker hands" % ", ".join(sorted(social)))
        else:
            add(ACTOR_COMPROMISED, 0.6,
                "authentication passes and aligns, so the message was sent through the "
                "domain's own infrastructure")
        if (domain_age_days or 0) > 365:
            add(ACTOR_COMPROMISED, 1.0,
                "sending domain is established (%d days old), so it was not registered "
                "for this campaign" % int(domain_age_days or 0))
    if "hdr.mass_recipients" in ids and aligned:
        add(ACTOR_COMPROMISED, 0.8,
            "bulk recipient list sent from an aligned domain suggests a hijacked mailbox")

    # -- direct actor ------------------------------------------------------
    if domain_age_days is not None and domain_age_days <= 30:
        add(
            ACTOR_DIRECT,
            2.0,
            "sending domain was registered %d day(s) ago - acquired for this activity" %
            int(domain_age_days))
    if {"id.lookalike_domain",
        "id.confusable_chars",
            "id.punycode_sender"} & ids:
        add(ACTOR_DIRECT, 1.2,
            "attacker-controlled lookalike domain rather than a hijacked one")
    if any(m in ind_text for m in HOSTING_MARKERS) and not any(
            m in ind_text for m in ANON_MARKERS):
        add(ACTOR_DIRECT, 0.8,
            "origin is ordinary hosting infrastructure with no anonymising indicators")
    if "intel.abuse_reports" in ids:
        add(ACTOR_DIRECT, 0.6, "origin IP already carries abuse reports")
    if any(m in ind_text for m in BOTNET_MARKERS):
        add(ACTOR_ANONYMISED, 1.0,
            "origin is consistent with a dynamic residential range, which is typical of "
            "botnet-relayed mail")

    total = sum(scores.values())
    # An attribution hypothesis needs an adversary to attribute. A clean message
    # trivially matches the "aligned authentication" rule that also fits a
    # hijacked mailbox, so without this gate every legitimate email was labelled
    # "compromised-account" - a false accusation dressed up as analysis. Malicious
    # weight, not the verdict, is the test, because attribution runs before the
    # verdict is final.
    malicious_weight = sum(
        s.weight for s in case.signals if s.triggered and s.weight > 0)
    if malicious_weight < 1.5:
        att = Attribution(
            actor_type=ACTOR_UNKNOWN, confidence=0.0, confidence_band="low", reasons=[
                "no adversarial activity was established for this message, so no "
                "actor is attributed (total malicious evidence %.2f logit, below "
                "the 1.50 threshold)" %
                malicious_weight], source=SOURCE_COMPUTED)
    elif total <= 0:
        att = Attribution(
            actor_type=ACTOR_UNKNOWN, confidence=0.0, confidence_band="low", reasons=[
                "malicious activity was established, but no header, "
                "authentication or infrastructure evidence favours any "
                "one attribution hypothesis"], source=SOURCE_COMPUTED)
    else:
        ranked = sorted(scores.items(), key=lambda kv: -kv[1])
        winner, top = ranked[0]
        share = top / total
        # Evidence mass factor: caps confidence when the case rests on a single
        # weak indicator, regardless of how one-sided it is.
        mass = min(1.0, top / 4.0)
        confidence = round(100.0 * share * (0.55 + 0.45 * mass), 1)
        att = Attribution(
            actor_type=winner,
            # never 100: this is a hypothesis
            confidence=min(95.0, confidence),
            confidence_band=_band(confidence),
            reasons=why[winner][:6],
            alternatives=[{"actor_type": k, "score": round(v, 2), "reasons": why[k][:3]}
                          for k, v in ranked[1:] if v > 0],
            source=SOURCE_COMPUTED,
        )
    att.infrastructure = indicators[:8]
    att.origin_place = str(origin.get("place", ""))
    att.origin_precision = str(origin.get("precision", "unknown"))
    if correlation:
        att.cluster_id = correlation.get("cluster_id", "")
        att.cluster_size = int(correlation.get("cluster_size", 1))
        att.related_case_ids = [r["case_id"]
                                for r in correlation.get("related", [])]
        att.shared_indicators = correlation.get("shared_indicators", [])
        if att.cluster_size > 1:
            att.reasons.append("linked to %d other case(s) by %s"
                               % (att.cluster_size - 1,
                                  ", ".join(att.shared_indicators[:2]) or "shared artefacts"))
    att.notes = (
        "Attribution is a hypothesis derived from headers, authentication and "
        "infrastructure indicators. It identifies the likely *mechanism* of the "
        "send, not a person, and must not be presented as identification of an "
        "individual.")
    return att


def extract_iocs(case: Case) -> List[Ioc]:
    """Case artefacts as IOCs, ready for STIX/MISP export.

    Confidence is per-indicator: the sending domain of a message whose DMARC
    failed is a weaker indicator than the sha256 of an executable attachment.
    """
    out: List[Ioc] = []
    risk = case.verdict.risk_score or 0.0
    base = int(max(30.0, min(90.0, risk)))
    art = case_artefacts(case)
    for addr in art["sender"]:
        out.append(Ioc(ioc_type="email-addr", value=addr, confidence=base,
                       context="From address on %s" % case.case_number))
    for dom in art["domain"]:
        out.append(Ioc(ioc_type="domain-name", value=dom,
                   confidence=max(30, base - 10), context="sender-side domain"))
    for ip in art["ip"]:
        hop = next((h for h in case.relay_hops if h.ip == ip), None)
        out.append(
            Ioc(
                ioc_type="ipv4-addr",
                value=ip,
                confidence=base if (
                    hop and hop.index == 0) else max(
                    30,
                    base -
                    20),
                context="relay hop%s" %
                (" (origin)" if hop and hop.index == 0 else "")))
    for host in art["url_host"]:
        out.append(Ioc(ioc_type="domain-name", value=host, confidence=base,
                       context="link destination"))
    for u in case.parsed_email.urls[:20]:
        out.append(Ioc(ioc_type="url", value=u.url[:400], confidence=base,
                       context="embedded link"))
    for a in case.parsed_email.attachments:
        if a.sha256:
            out.append(Ioc(ioc_type="file-hash", value=a.sha256,
                           confidence=min(95, base + 10),
                           context="attachment %s (%s)" % (a.filename, a.detected_type)))
    seen = set()
    unique: List[Ioc] = []
    for ioc in out:
        key = (ioc.ioc_type, ioc.value.lower())
        if key not in seen and ioc.value:
            seen.add(key)
            unique.append(ioc)
    return unique
