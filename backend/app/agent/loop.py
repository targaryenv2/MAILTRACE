"""The agentic investigation loop.

What makes this an *agent* rather than a script: after every step the loop
re-reads the evidence it has accumulated and decides what to do next. Cheap,
deterministic checks run first; expensive or network-bound checks (WHOIS, DNS,
reputation, detonation) run only when the earlier evidence justifies them, and
the loop stops early when the case is already conclusive in either direction.

Concretely, the planner will:

* skip URL analysis entirely when the message has no links, rather than logging a
  no-op step;
* skip reputation lookups when the header analysis has already produced a
  conclusive verdict, to protect free-tier API quotas (the brief is explicit about
  this) - unless the origin looks anonymised, where attribution still needs them;
* escalate to WHOIS/DNS when identity checks suggest a lookalike or newly
  registered domain, because domain age is the deciding evidence there;
* detonate links only when a link is the payload *and* detonation is enabled;
* always run the ML model, then stop and hand over to a human if the model and the
  rules disagree materially - see ``detection.engine.build_verdict``.

Every step records ``reasoning``: the sentence explaining why *this* check was
chosen given what the previous step returned. That field is what an analyst reads
to decide whether they trust the conclusion, and what the PDF prints as the
investigation narrative.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..config import get_settings
from ..detection.engine import build_verdict, check_relay, run_rules
from ..geoip.resolver import build_relay_path, origin_summary
from ..graph.correlate import attribute, build_graph, correlate_cases, extract_iocs
from ..intel.client import get_intel_client, intel_signals
from ..ml.predict import get_classifier
from ..mitre.attack import enrich_signals, techniques_for_case
from ..privacy.redact import safe_log_fields
from ..sandbox.detonate import detonate_all, sandbox_signals
from ..schemas import (
    Case,
    IntelResult,
    MlPrediction,
    Signal,
    SOURCE_COMPUTED,
    STEP_FAILED,
    STEP_OK,
    STEP_SKIPPED,
    TrailStep,
    VERDICT_PHISHING,
    utcnow,
)
from ..workflow.triage import (
    blast_radius,
    campaign_for,
    classify_threat,
    containment_priority,
    next_actions,
    start_sla,
    takedown_draft,
)

log = logging.getLogger(__name__)

# Risk bands outside which more evidence will not change the answer. Kept as
# settings rather than constants because a SOC with different tolerance for false
# negatives will want to move them.


def _thresholds() -> Tuple[float, float]:
    st = get_settings()
    return st.conclusive_low, st.conclusive_high


def _severity_of(weight: float) -> str:
    return ("critical" if weight >= 2.0 else "high" if weight >= 1.4
            else "medium" if weight >= 0.7 else "low")


def _signals_from_dicts(
        rows: Sequence[Dict[str, Any]], category: str) -> List[Signal]:
    out: List[Signal] = []
    for row in rows:
        out.append(Signal(
            id=str(row.get("id", "%s.unknown" % category)),
            signal_type=category,
            title=str(row.get("title", "")),
            result=str(row.get("result", ""))[:300],
            weight=float(row.get("weight", 0.0)),
            severity=str(row.get("severity", _severity_of(float(row.get("weight", 0.0))))),
            category=category,
            evidence=str(row.get("evidence", ""))[:600],
            detail=dict(row.get("detail", {})),
            source=str(row.get("source", SOURCE_COMPUTED)),
        ))
    return out


class Investigation:
    """One case, one investigation. Not reused across cases: the trail, the timing
    and the accumulated evidence are all per-case state."""

    def __init__(self,
                 case: Case,
                 existing: Optional[Sequence[Case]] = None,
                 chain: Any = None,
                 on_step: Optional[Callable[[TrailStep],
                                            None]] = None):
        self.case = case
        self.existing = list(existing or [])
        self.chain = chain
        self.on_step = on_step
        self.step_index = 0
        self.coverage = 0.0          # fraction of planned evidence sources that answered
        self.planned = 0
        self.answered = 0
        self.intel_results: List[IntelResult] = []
        self.domain_age: Optional[int] = None
        self.correlation: Dict[str, Any] = {}

    # -- trail -------------------------------------------------------------

    def _step(self, action: str, reasoning: str, fn: Callable[[
    ], Tuple[str, Dict[str, Any], List[Signal]]], ) -> TrailStep:
        """Run one investigation step, timing it and capturing failures.

        A step that raises degrades the case rather than aborting it: a WHOIS
        timeout should not lose the header analysis that already succeeded.
        """
        started = time.time()
        step = TrailStep(
            index=self.step_index,
            action=action,
            reasoning=reasoning,
            started_at=utcnow(),
            result="")
        self.step_index += 1
        try:
            result, detail, signals = fn()
            step.result = result
            step.detail = detail
            step.signals_added = [s.id for s in signals]
            self.case.signals.extend(signals)
            step.status = STEP_OK
        except Exception as exc:  # noqa: BLE001 - one failed check must not kill the case
            step.status = STEP_FAILED
            step.result = "step failed: %s" % str(exc)[:200]
            self.case.errors.append("%s: %s" % (action, str(exc)[:200]))
            log.warning(
                "step failed",
                extra=safe_log_fields(
                    self.case.id,
                    action=action,
                    error=str(exc)[
                        :120]))
        step.finished_at = utcnow()
        step.duration_ms = int((time.time() - started) * 1000)
        self.case.trail.append(step)
        if self.chain is not None:
            try:
                receipt = self.chain.record_step(
                    self.case.id, step.index, action, step.result[:200])
                step.tx_hash = receipt.tx_hash
                self.case.chain_receipts.append(receipt)
            except Exception as exc:  # noqa: BLE001
                log.warning("custody append failed: %s", str(exc)[:120])
        if self.on_step is not None:
            try:
                self.on_step(step)
            except Exception:  # noqa: BLE001 - a broken subscriber must not stop the case
                log.debug("step subscriber raised", exc_info=True)
        return step

    def _skip(self, action: str, reasoning: str, result: str) -> None:
        """Record a *decision not to run* a check. This is evidence too: a report
        that silently omits a check cannot be reviewed."""
        step = TrailStep(
            index=self.step_index,
            action=action,
            reasoning=reasoning,
            result=result,
            status=STEP_SKIPPED,
            started_at=utcnow(),
            finished_at=utcnow(),
            duration_ms=0)
        self.step_index += 1
        self.case.trail.append(step)
        if self.on_step is not None:
            try:
                self.on_step(step)
            except Exception:  # noqa: BLE001
                log.debug("step subscriber raised", exc_info=True)

    # -- interim scoring ---------------------------------------------------

    def _interim(self) -> float:
        from ..detection.engine import score
        return score(self.case.signals)[0]

    def _conclusive(self) -> Tuple[bool, str]:
        low, high = _thresholds()
        risk = self._interim()
        if risk >= high:
            return True, ("header, identity and content evidence already puts this at "
                          "%.1f/100, above the conclusive threshold of %.0f" % (risk, high))
        if risk <= low:
            return True, ("nothing found so far: %.1f/100, below the conclusive threshold "
                          "of %.0f" % (risk, low))
        return False, ("interim risk %.1f/100 sits in the ambiguous band, so more evidence "
                       "is worth gathering" % risk)

    # -- the loop ----------------------------------------------------------

    def run(self) -> Case:
        case, p = self.case, self.case.parsed_email
        case.sla = case.sla if case.sla.deadline_at else start_sla()

        # 1. deterministic header, identity and content analysis -------------
        self._step(
            "header_and_content_analysis",
            "Always first: it is free, needs no network, and it determines which of the "
            "expensive checks are worth running at all.",
            lambda: self._rules(),
        )

        # 2. relay reconstruction -------------------------------------------
        if p.received_chain:
            self._step(
                "relay_path_reconstruction",
                "The message carries %d Received header(s), so the sending path can be "
                "reconstructed and the earliest reliable node geolocated." % len(
                    p.received_chain),
                lambda: self._relay(),
            )
        else:
            self._skip(
                "relay_path_reconstruction",
                "No Received headers survived, so there is no path to reconstruct.",
                "skipped: no Received chain (itself recorded as a signal)")

        # 3. ML second opinion ----------------------------------------------
        self._step(
            "ml_classification",
            "Run the trained classifier independently of the rules so that a "
            "well-written message with clean headers still gets a content-based "
            "opinion, and so disagreement between the two can be detected.",
            lambda: self._ml(),
        )

        # 4. decide whether enrichment is justified -------------------------
        conclusive, why = self._conclusive()
        anonymised = any("tor" in " ".join(h.anomaly_reasons).lower()
                         or "proxy" in (h.hostname or "").lower()
                         for h in case.relay_hops)
        identity_doubt = any(
            s.id.startswith(
                ("id.lookalike",
                 "id.brand",
                 "id.confusable",
                 "id.punycode",
                 "id.suspicious_tld")) for s in case.signals if s.triggered)
        want_intel = (not conclusive) or anonymised or identity_doubt

        if want_intel:
            reason = why
            if conclusive and anonymised:
                reason += ("; enriching anyway because the origin looks anonymised and "
                           "attribution needs the reputation data")
            elif conclusive and identity_doubt:
                reason += (
                    "; enriching anyway because domain age is the deciding evidence "
                    "for a suspected lookalike domain")
            self._step(
                "threat_intel_enrichment",
                reason,
                lambda: self._intel())
        else:
            self._skip(
                "threat_intel_enrichment",
                why + "; skipping reputation lookups preserves free-tier API quota "
                "for cases that actually need them.",
                "skipped: verdict already conclusive from local evidence")

        # 5. link detonation -------------------------------------------------
        st = get_settings()
        risky = [u.url for u in p.urls]
        if risky and (st.allow_detonation and st.allow_network):
            self._step(
                "link_detonation",
                "The payload is a link (%d found) and detonation is enabled, so the "
                "landing page is opened in a disposable headless context." %
                len(risky),
                lambda: self._sandbox(risky))
        elif risky:
            self._step(
                "link_static_analysis",
                "Detonation is disabled, so the links are analysed as strings only - "
                "structure, encoding tricks and brand keywords - with nothing fetched.",
                lambda: self._sandbox(risky))
        else:
            self._skip(
                "link_analysis",
                "The message contains no links, so there is nothing to analyse or "
                "detonate.",
                "skipped: no URLs in the message")

        # 6. correlation and attribution -------------------------------------
        self._step(
            "identity_correlation",
            "Link this case to earlier ones through shared senders, domains, relay "
            "IPs and attachment digests, so a wave is visible as a wave.",
            lambda: self._correlate())
        self._step(
            "attribution",
            "Decide which attribution hypothesis the evidence supports - compromised "
            "account, spoofed domain, anonymised infrastructure or direct actor - "
            "because each implies a different response.",
            lambda: self._attribute())

        # 7. verdict ----------------------------------------------------------
        self._step(
            "verdict_and_classification",
            "Combine every signal as log-odds, compute confidence separately from "
            "risk, and route to a human when the two disagree.",
            lambda: self._verdict())

        # 8. impact and response ---------------------------------------------
        self._step(
            "blast_radius_and_response",
            "Establish who else received the wave and turn the verdict into concrete "
            "containment steps an analyst can execute.",
            lambda: self._impact())

        case.status = "awaiting_approval" if case.verdict.requires_human_review else "cleared"
        case.completed_at = utcnow()
        case.updated_at = case.completed_at
        case.capabilities = st.capability_report()
        if self.chain is not None:
            try:
                receipt = self.chain.record_verdict(
                    case.id, case.verdict.label, int(case.verdict.risk_score),
                    int(case.verdict.confidence))
                case.chain_receipts.append(receipt)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "verdict custody append failed: %s",
                    str(exc)[
                        :120])
        log.info("case complete", extra=safe_log_fields(
            case.id, verdict=case.verdict.label, risk=case.verdict.risk_score,
            confidence=case.verdict.confidence, steps=len(case.trail)))
        return case

    # -- step bodies -------------------------------------------------------

    def _rules(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        signals = run_rules(self.case.parsed_email)
        self.planned += 1
        self.answered += 1
        auth = self.case.parsed_email.auth
        triggered = [s for s in signals if s.triggered]
        summary = (
            "%d signal(s) from headers, identity and content; SPF=%s DKIM=%s DMARC=%s "
            "(aligned: spf=%s dkim=%s)" %
            (len(triggered),
             auth.spf or "none",
             auth.dkim or "none",
             auth.dmarc or "none",
             auth.spf_aligned,
             auth.dkim_aligned))
        return summary, {"signals": len(triggered), "spf": auth.spf, "dkim": auth.dkim,
                         "dmarc": auth.dmarc, "spf_aligned": auth.spf_aligned,
                         "dkim_aligned": auth.dkim_aligned}, signals

    def _relay(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        self.planned += 1
        hops = build_relay_path(self.case.parsed_email.received_chain)
        self.case.relay_hops = hops
        self.case.origin = origin_summary(hops)
        signals = check_relay(hops)
        if hops:
            self.answered += 1
        origin = self.case.origin
        summary = (
            "%d hop(s); earliest reliable node %s at %s (%s precision, %s confidence)" %
            (len(hops), origin.get(
                "ip", "unknown"), origin.get(
                "place", "unresolved"), origin.get(
                "precision", "unknown"), origin.get(
                    "confidence", "none")))
        return summary, dict(origin), signals

    def _ml(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        self.planned += 1
        clf = get_classifier()
        pred: MlPrediction = clf.predict(self.case.parsed_email)
        self.case.ml = pred
        signals: List[Signal] = []
        if pred.available:
            self.answered += 1
            from ..detection.engine import ml_signal
            sig = ml_signal(pred)
            if sig is not None:
                signals.append(sig)
            if any("Spearphish Override" in str(n) for n in (pred.notes or [])):
                spear_notes = [str(n) for n in pred.notes if "Spearphish Override" in str(n)][0]
                signals.append(Signal(
                    id="ml.spearphish_override",
                    signal_type="spearphish",
                    title="Spearphishing pattern detected",
                    result="Professional framing masking malicious payload link",
                    weight=2.5,
                    severity="high",
                    category="heuristic",
                    evidence=spear_notes,
                    detail={"spearphish": True},
                    source="computed",
                ))
            top = ", ".join("%s %+.3f" % (f.feature, f.contribution)
                            for f in pred.top_features[:4])

            summary = (
                "model %s v%s: p(phish)=%.3f -> %s; top contributions: %s" %
                (pred.model_name,
                 pred.model_version,
                 pred.probability or 0.0,
                 pred.label,
                 top or "none"))
        else:
            summary = "model unavailable (%s); rules only" % (
                pred.notes or "not trained")
        return summary, {"probability": pred.probability,
                         "available": pred.available, "base_value": pred.base_value}, signals

    def _intel(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        from concurrent.futures import ThreadPoolExecutor
        p = self.case.parsed_email
        client = get_intel_client()
        results: List[IntelResult] = []
        domains = [d for d in {p.from_domain} if d]
        for u in p.urls[:3]:
            if u.registrable_domain and u.registrable_domain not in domains:
                domains.append(u.registrable_domain)
        ips = [h.ip for h in self.case.relay_hops[:2]
               if h.ip and not h.is_private]

        tasks = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for dom in domains[:3]:
                tasks.append(("whois", dom, pool.submit(client.whois_domain, dom)))
                tasks.append(("dns", dom, pool.submit(client.domain_dns, dom)))
            for ip in ips:
                tasks.append(("abuse", ip, pool.submit(client.abuseipdb, ip)))
                tasks.append(("rdns", ip, pool.submit(client.reverse_dns, ip)))
                tasks.append(("bl", ip, pool.submit(client.blacklist_check, ip)))
            for u in p.urls[:2]:
                tasks.append(("vt", u.url, pool.submit(client.virustotal_url, u.url)))

            self.planned += len(tasks)
            for kind, subject, fut in tasks:
                try:
                    res = fut.result()
                    results.append(res)
                    if res.status == "ok":
                        self.answered += 1
                        if kind == "whois" and subject == p.from_domain:
                            age = res.data.get("domain_age_days")
                            self.domain_age = int(age) if isinstance(age, (int, float)) else None
                except Exception as e:
                    log.warning("intel lookup error: %s", e)


        self.intel_results = results
        self.case.intel = results
        signals = _signals_from_dicts(intel_signals(results), "intel")
        ok = [r for r in results if r.status == "ok"]
        sources = sorted({r.source for r in ok})
        summary = ("%d/%d lookup(s) answered from %s; %d signal(s) raised%s"
                   % (len(ok), len(results), "/".join(sources) or "nothing",
                      len(signals),
                      "; sending domain is %d day(s) old" % self.domain_age
                      if self.domain_age is not None else ""))
        return summary, {"providers": [r.provider for r in results],
                         "answered": len(ok), "domain_age_days": self.domain_age,
                         "sources": sources}, signals

    def _sandbox(self, urls: List[str]) -> Tuple[str,
                                                 Dict[str, Any], List[Signal]]:
        self.planned += 1
        results = detonate_all(urls, limit=3)
        self.case.sandbox = results
        if results:
            self.answered += 1
        signals = _signals_from_dicts(sandbox_signals(results), "sandbox")
        summary = "; ".join("%s -> %s (%s)" % (r.url[:48], r.verdict, r.status)
                            for r in results) or "no URLs analysed"
        return summary[:400], {"analysed": len(results),
                               "statuses": [r.status for r in results]}, signals

    def _correlate(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        from ..graph.correlate import fingerprint as case_fingerprint
        self.case.fingerprint = self.case.fingerprint or case_fingerprint(
            self.case)
        self.correlation = correlate_cases(self.case, self.existing)
        related_ids = set(
            self.correlation.get("cluster_id") and [
                r["case_id"] for r in self.correlation["related"]] or [])
        related_cases = [c for c in self.existing if c.id in related_ids]
        self.case.campaign = campaign_for(self.case, self.existing)
        nodes, edges = build_graph(self.case, related_cases)
        self.case.attribution.nodes = nodes
        self.case.attribution.edges = edges
        summary = (
            "cluster of %d case(s); campaign %s (%d message(s)%s); graph has %d node(s) "
            "and %d edge(s)" %
            (self.correlation.get(
                "cluster_size",
                1),
                self.case.campaign.id,
                self.case.campaign.case_count,
                ", duplicate of %s" %
                self.case.campaign.merged_into if self.case.campaign.is_duplicate else "",
                len(nodes),
                len(edges)))
        return summary, {"cluster_id": self.correlation.get("cluster_id", ""),
                         "shared": self.correlation.get("shared_indicators", []),
                         "nodes": len(nodes), "edges": len(edges)}, []

    def _attribute(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        nodes, edges = self.case.attribution.nodes, self.case.attribution.edges
        att = attribute(self.case, self.correlation, self.domain_age)
        att.nodes, att.edges = nodes, edges
        self.case.attribution = att
        summary = (
            "%s at %.0f%% confidence (%s): %s" %
            (att.actor_type,
             att.confidence,
             att.confidence_band,
             att.reasons[0] if att.reasons else "no supporting evidence"))
        return summary[:400], {"actor_type": att.actor_type, "confidence": att.confidence,
                               "alternatives": [a["actor_type"] for a in att.alternatives]}, []

    def _verdict(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        self.case.signals = enrich_signals(self.case.signals)
        coverage = (self.answered / self.planned) if self.planned else 0.0
        self.coverage = round(coverage, 3)
        self.case.verdict = build_verdict(
            self.case.signals, self.case.ml, coverage)
        threat, why = classify_threat(self.case)
        self.case.verdict.threat_class = threat
        self.case.verdict.threat_class_reason = why
        self.case.mitre = techniques_for_case(self.case.signals)
        self.case.iocs = extract_iocs(self.case)
        v = self.case.verdict
        summary = (
            "%s / %s: risk %.1f (%s), confidence %.1f%% (%s), evidence coverage %.0f%%" %
            (v.label,
             threat,
             v.risk_score,
             v.risk_level,
             v.confidence,
             v.confidence_band,
             coverage *
             100))
        return summary, {"risk": v.risk_score, "confidence": v.confidence,
                         "threat_class": threat, "coverage": self.coverage,
                         "flags": v.ambiguity_flags,
                         "techniques": [m["technique"] for m in self.case.mitre]}, []

    def _impact(self) -> Tuple[str, Dict[str, Any], List[Signal]]:
        related_ids = {r["case_id"]
                       for r in self.correlation.get("related", [])}
        related = [c for c in self.existing if c.id in related_ids]
        self.case.blast_radius = blast_radius(self.case, related)
        priority = containment_priority(
            self.case.blast_radius,
            self.case.verdict.risk_score)
        actions = next_actions(self.case)
        self.case.blast_radius.notes = (self.case.blast_radius.notes + " " +
                                        "priority: %s" % priority).strip()
        if self.case.verdict.label == VERDICT_PHISHING:
            lookup = {}
            for r in self.intel_results:
                if r.provider == "whois" and r.status == "ok":
                    lookup[r.subject] = r.data
            self.case.takedown = takedown_draft(self.case, lookup)
        radius = self.case.blast_radius
        summary = (
            "%s; %d recipient(s), %d clicked, %d high-value; %d response step(s)" %
            (priority,
             radius.total_recipients,
             radius.total_clicked,
             radius.high_value_targets,
             len(actions)))
        return summary, {"priority": priority, "actions": actions,
                         "takedown": bool(self.case.takedown)}, []


def investigate(case: Case,
                existing: Optional[Sequence[Case]] = None,
                chain: Any = None,
                on_step: Optional[Callable[[TrailStep],
                                           None]] = None) -> Case:
    """Run the full investigation on ``case`` and return it, mutated in place."""
    return Investigation(case, existing, chain, on_step).run()
