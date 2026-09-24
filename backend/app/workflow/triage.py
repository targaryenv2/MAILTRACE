"""Analyst workflow: blast radius, campaign dedup, IOC export, takedown, SLA, HITL.

These are the parts that turn a detection score into something a SOC can act on,
and each one exists to answer a question an analyst asks in the first two minutes
of a real ticket:

* *who else got this?* -> :func:`blast_radius`
* *have we seen it before?* -> :func:`campaign_for`
* *what do I block?* -> :func:`export_iocs`
* *who do I tell?* -> :func:`takedown_draft`
* *how long have I got?* -> :func:`start_sla` / :func:`sla_state`
* *who decided?* -> :func:`record_decision`

Exposure data is the one thing MailTrace cannot compute: it lives in the mail
gateway. Rather than invent it, exposure is read from
``data/fixtures/org_directory.json`` and every derived number carries
``source="fixture"`` so the dashboard labels it. Wire a real gateway in by
replacing :func:`load_directory`.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..config import DATA_DIR, get_settings
from ..graph.correlate import extract_iocs, fingerprint
from ..schemas import (
    ACTOR_COMPROMISED,
    ACTOR_SPOOFED,
    BlastRadius,
    Case,
    CampaignRef,
    ExposureRecord,
    Ioc,
    SOURCE_COMPUTED,
    SOURCE_FIXTURE,
    SOURCE_UNAVAILABLE,
    SlaState,
    STATUS_APPROVED,
    STATUS_ESCALATED,
    STATUS_OVERRIDDEN,
    TakedownDraft,
    THREAT_FRAUD,
    THREAT_IMPERSONATED,
    THREAT_LEGITIMATE,
    THREAT_PHISHING,
    THREAT_SUSPICIOUS,
    VERDICT_BENIGN,
    VERDICT_LIKELY_BENIGN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    utcnow,
)

log = logging.getLogger(__name__)

DIRECTORY_PATH = DATA_DIR / "fixtures" / "org_directory.json"
HIGH_VALUE_ROLES = ("cfo", "ceo", "cto", "coo", "director", "vp", "head",
                    "finance", "payroll", "treasury", "admin", "hr")

_directory_cache: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# blast radius
# ---------------------------------------------------------------------------


def load_directory() -> Dict[str, Any]:
    """Load the exposure fixture. Missing file is normal, not an error."""
    global _directory_cache
    if _directory_cache is not None:
        return _directory_cache
    try:
        _directory_cache = json.loads(
            DIRECTORY_PATH.read_text(
                encoding="utf-8"))
    except (OSError, ValueError):
        _directory_cache = {}
    return _directory_cache


def reset_directory() -> None:
    global _directory_cache
    _directory_cache = None


def _is_high_value(role: str, department: str) -> bool:
    text = ("%s %s" % (role, department)).lower()
    return any(word in text for word in HIGH_VALUE_ROLES)


def blast_radius(case: Case,
                 related: Optional[Sequence[Case]] = None) -> BlastRadius:
    """Who else received this wave, and how far did it get.

    Matching is by campaign fingerprint rather than by exact subject, because the
    same wave arrives with per-victim subject variations; see
    ``graph.correlate.fingerprint`` for what is held constant.
    """
    fp = case.fingerprint or fingerprint(case)
    directory = load_directory()
    waves = directory.get("waves", {})
    entry = waves.get(fp) or waves.get(
        case.parsed_email.from_domain.lower(), {})
    out = BlastRadius(fingerprint=fp, source=SOURCE_FIXTURE)

    people: List[Dict[str, Any]] = list(entry.get("recipients", []))
    matched: List[str] = []
    if people:
        matched.append(
            "gateway wave fixture keyed on the campaign fingerprint")
    # Recipients visible in the message itself are always counted, fixture or not:
    # they are first-party evidence from the headers.
    header_recipients = [r for r in (case.parsed_email.to or []) if "@" in r]
    header_recipients += [r for r in (case.parsed_email.cc or []) if "@" in r]
    known = {str(p.get("email", "")).lower() for p in people}
    for addr in header_recipients:
        if addr.lower() not in known:
            people.append({"email": addr, "delivered": True})
            known.add(addr.lower())
    if header_recipients:
        matched.append("To/Cc headers on the message itself")
    for other in related or ():
        addr = other.recipient
        if addr and addr.lower() not in known:
            people.append({"email": addr, "delivered": True, "reported": True})
            known.add(addr.lower())
    if related:
        matched.append("recipients of %d correlated case(s)" %
                       len(list(related)))

    staff = {str(p.get("email", "")).lower()             : p for p in directory.get("staff", [])}
    for person in people:
        email = str(person.get("email", ""))
        profile = staff.get(email.lower(), {})
        role = str(person.get("role", profile.get("role", "")))
        dept = str(person.get("department", profile.get("department", "")))
        rec = ExposureRecord(
            recipient_email=email,
            display_name=str(person.get("name", profile.get("name", ""))),
            department=dept, role=role,
            delivered=bool(person.get("delivered", True)),
            opened=bool(person.get("opened", False)),
            clicked=bool(person.get("clicked", False)),
            submitted_credentials=bool(person.get("submitted_credentials", False)),
            reported=bool(person.get("reported", False)),
            is_high_value=_is_high_value(role, dept),
            last_event_at=str(person.get("last_event_at", "")),
        )
        out.exposures.append(rec)

    out.matched_by = matched
    out.total_recipients = len(out.exposures)
    out.total_opened = sum(1 for e in out.exposures if e.opened)
    out.total_clicked = sum(1 for e in out.exposures if e.clicked)
    out.total_credentials_submitted = sum(
        1 for e in out.exposures if e.submitted_credentials)
    out.total_reported = sum(1 for e in out.exposures if e.reported)
    out.high_value_targets = sum(1 for e in out.exposures if e.is_high_value)
    out.departments_affected = sorted(
        {e.department for e in out.exposures if e.department})
    out.is_campaign = out.total_recipients > 1
    if not out.exposures:
        out.source = SOURCE_UNAVAILABLE
        out.notes = (
            "no exposure data: connect a mail gateway or add a wave to "
            "data/fixtures/org_directory.json. Recipient counts are not inferred.")
    elif entry:
        out.notes = (
            "delivery, open and click counts come from an illustrative gateway "
            "fixture and are labelled as such; header-derived recipients are "
            "first-party evidence.")
    else:
        out.source = SOURCE_COMPUTED
        out.notes = "recipients derived from the message headers and correlated cases only."
    return out


def containment_priority(radius: BlastRadius, risk: float) -> str:
    """One line the queue can sort on: exposure severity, not just message risk.

    A medium-risk mail that reached the CFO outranks a high-risk mail that landed
    in one unopened mailbox, and the queue should say so.
    """
    if radius.total_credentials_submitted:
        return "P1 - credentials submitted, force reset now"
    if radius.total_clicked and radius.high_value_targets:
        return "P1 - high-value target clicked"
    if radius.total_clicked:
        return "P2 - link clicked, isolate and reset"
    if risk >= 80 and radius.total_recipients > 5:
        return "P2 - high-risk wave delivered to %d mailboxes" % radius.total_recipients
    if radius.high_value_targets:
        return "P3 - high-value target in recipient list"
    if risk >= 45:
        return "P3 - suspicious, quarantine pending review"
    return "P4 - monitor"


# ---------------------------------------------------------------------------
# campaign dedup
# ---------------------------------------------------------------------------


def campaign_for(case: Case, existing: Sequence[Case],
                 window_hours: int = 168) -> CampaignRef:
    """Group the case into a campaign, and mark it duplicate when appropriate.

    A duplicate is *not* discarded - the count is what tells the analyst the wave
    is ongoing. It is suppressed from the alert stream instead, which is the
    behaviour that keeps a live queue usable.
    """
    fp = case.fingerprint or fingerprint(case)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    siblings = []
    for other in existing:
        if other.id == case.id:
            continue
        if (other.fingerprint or fingerprint(other)) != fp:
            continue
        when = _parse_iso(other.created_at)
        if when is None or when >= cutoff:
            siblings.append(other)
    siblings.sort(key=lambda c: c.created_at)
    ref = CampaignRef(fingerprint=fp, case_count=len(siblings) + 1)
    if siblings:
        first = siblings[0]
        ref.id = first.campaign.id or ("camp-%s" % fp[:12])
        ref.first_seen = first.created_at
        ref.related_case_ids = [c.id for c in siblings]
        ref.is_duplicate = True
        ref.merged_into = first.id
    else:
        ref.id = "camp-%s" % fp[:12]
        ref.first_seen = case.created_at
    return ref


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# threat classification (PS-26106 five-way)
# ---------------------------------------------------------------------------


def classify_threat(case: Case) -> Tuple[str, str]:
    """Map the case onto the problem statement's five categories.

    This is a second axis, not a rename of the verdict: the verdict says how
    confident we are that the mail is malicious, this says *what kind*. Fraud and
    phishing are separated because they need different responses - fraud is a
    finance-process failure, phishing is a credential compromise.
    """
    ids = {s.id.rsplit(".", 1)[0] if s.id[-1].isdigit() else s.id
           for s in case.signals if s.triggered}
    v = case.verdict.label
    impersonation = bool({"id.brand_impersonation",
                          "id.lookalike_domain",
                          "id.confusable_chars",
                          "id.punycode_sender",
                          "id.name_contains_other_address",
                          "auth.spf_unaligned"} & ids)
    fraud = bool({"nlp.payment_diversion",
                  "nlp.bec_no_payload",
                  "nlp.secrecy"} & ids)
    credential = bool({"nlp.credential_lure", "url.credential_path",
                       "sandbox.credential_form"} & ids)

    if v in (
        VERDICT_BENIGN,
    ) or (
            v == VERDICT_LIKELY_BENIGN and not ids -
            {"ml.score"}):
        return THREAT_LEGITIMATE, "no malicious indicators of any category fired"
    if v == VERDICT_PHISHING and credential:
        return THREAT_PHISHING, "credential-harvesting intent with a high-confidence verdict"
    if fraud and not credential:
        return (
            THREAT_FRAUD,
            "financial-fraud framing (payment redirection or a payload-free money ask) "
            "rather than credential theft")
    if impersonation and v in (VERDICT_PHISHING, VERDICT_SUSPICIOUS):
        return (
            THREAT_IMPERSONATED,
            "the sender identity itself is forged or imitated; the ask is secondary")
    if v == VERDICT_PHISHING:
        return THREAT_PHISHING, "multiple independent phishing indicators"
    return THREAT_SUSPICIOUS, "indicators present but not sufficient for a firm category"


# ---------------------------------------------------------------------------
# IOC export
# ---------------------------------------------------------------------------

_STIX_TYPE = {
    "ipv4-addr": "ipv4-addr:value",
    "domain-name": "domain-name:value",
    "url": "url:value",
    "email-addr": "email-addr:value",
    "file-hash": "file:hashes.'SHA-256'"}
_MISP_TYPE = {"ipv4-addr": "ip-src", "domain-name": "domain", "url": "url",
              "email-addr": "email-src", "file-hash": "sha256"}


def _stix_id(kind: str, value: str) -> str:
    import hashlib
    import uuid
    # STIX 2.1 deterministic UUIDv5 in the STIX namespace, so re-exporting the
    # same case does not create duplicate objects in the consumer's platform.
    ns = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    return "indicator--%s" % uuid.uuid5(ns, "%s:%s" % (kind, value.lower()))


def export_iocs(case: Case, fmt: str = "stix") -> Dict[str, Any]:
    """Export the case IOCs as STIX 2.1 bundle or MISP event.

    Both formats are emitted from the same :class:`Ioc` list so a mismatch between
    what the UI shows and what the SIEM ingests is impossible.
    """
    iocs = case.iocs or extract_iocs(case)
    now = utcnow()
    if fmt == "misp":
        return {
            "Event": {
                "info": "MailTrace %s - %s" % (case.case_number, case.verdict.label),
                "date": now[:10], "threat_level_id": "2" if case.verdict.risk_score >= 80 else "3",
                "analysis": "1", "distribution": "0",
                "Attribute": [{
                    "type": _MISP_TYPE.get(i.ioc_type, "other"), "value": i.value,
                    "category": "Payload delivery" if i.ioc_type == "file-hash"
                                else "Network activity",
                    "to_ids": i.confidence >= 60, "comment": i.context,
                } for i in iocs],
                "Tag": [{"name": 'mailtrace:verdict="%s"' % case.verdict.label},
                        {"name": 'mailtrace:threat-class="%s"' % case.verdict.threat_class}] +
                [{"name": "mitre-attack-pattern:%s" % m.get("technique", "")}
                 for m in case.mitre[:6]],
            }
        }
    objects: List[Dict[str, Any]] = []
    for i in iocs:
        path = _STIX_TYPE.get(i.ioc_type)
        if not path:
            continue
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _stix_id(i.ioc_type, i.value),
            "created": now, "modified": now,
            "name": "%s observed in %s" % (i.ioc_type, case.case_number),
            "description": i.context, "confidence": int(i.confidence),
            "indicator_types": ["malicious-activity"],
            "pattern": "[%s = '%s']" % (path, i.value.replace("'", "\\'")),
            "pattern_type": "stix", "valid_from": i.first_seen,
            "labels": [case.verdict.label, case.verdict.threat_class],
        })
    return {"type": "bundle", "id": "bundle--%s" % case.id, "objects": objects}


# ---------------------------------------------------------------------------
# takedown draft
# ---------------------------------------------------------------------------


def takedown_draft(case: Case,
                   intel_lookup: Optional[Dict[str,
                                               Any]] = None) -> TakedownDraft:
    """Draft an abuse report. MailTrace drafts; a human sends.

    Auto-sending abuse mail from a detection tool is how false positives become
    someone else's outage, so ``sent`` is hard-wired to False and the analyst
    copies the text out.
    """
    p = case.parsed_email
    target = ""
    for u in p.urls:
        if u.registrable_domain:
            target = u.registrable_domain
            break
    target = target or p.from_domain
    info = (intel_lookup or {}).get(target, {}) if intel_lookup else {}
    registrar = str(info.get("registrar", ""))
    abuse_to = str(
        info.get(
            "abuse_contact",
            "")) or (
        "abuse@%s" %
        target if target else "")
    hops = ", ".join("%s (%s)" % (h.ip, h.location.country or "location unresolved")
                     for h in case.relay_hops[:3] if h.ip)
    tech = ", ".join("%s %s" % (m.get("technique"), m.get("name"))
                     for m in case.mitre[:3])
    body = (
        "To whom it may concern,\n\n"
        "We are reporting abuse of infrastructure associated with %(target)s, used in a "
        "phishing message received by our organisation on %(when)s.\n\n"
        "Case reference: %(case)s\n"
        "Assessment: %(verdict)s (risk %(risk).0f/100, confidence %(conf).0f%%, "
        "classification: %(threat)s)\n"
        "Sending domain: %(from_domain)s\n"
        "Message-ID: %(mid)s\n"
        "Raw message SHA-256: %(hash)s\n"
        "Earliest reliable sending node: %(origin)s\n"
        "Relay path: %(hops)s\n"
        "Malicious URLs:\n%(urls)s\n"
        "Technique mapping: %(tech)s\n\n"
        "Evidence summary:\n%(evidence)s\n\n"
        "The full forensic report, including the header chain, authentication results and "
        "a tamper-evident chain of custody, is available on request. Recipient identities "
        "have been withheld under our data-protection policy and can be provided to the "
        "registrar or to law enforcement through the appropriate channel.\n\n"
        "We request suspension of the domain and preservation of the associated logs.\n\n"
        "Regards,\nSecurity Operations\n"
    ) % {
        "target": target or "the reported domain",
        "when": (p.date or case.created_at)[:19],
        "case": case.case_number, "verdict": case.verdict.label,
        "risk": case.verdict.risk_score, "conf": case.verdict.confidence,
        "threat": case.verdict.threat_class,
        "from_domain": p.from_domain or "unknown",
        "mid": p.message_id or "absent",
        "hash": p.raw_sha256 or case.email_hash,
        "origin": str((case.origin or {}).get("place", "not established")),
        "hops": hops or "not reconstructable from the headers",
        "urls": "\n".join("  - %s" % u.url[:200] for u in p.urls[:8]) or "  - none",
        "tech": tech or "not mapped",
        "evidence": "\n".join("  - %s: %s" % (s.title, s.result[:100])
                              for s in case.signals if s.triggered and s.weight > 0.8)[:1400]
                    or "  - see attached report",
    }
    return TakedownDraft(
        target_domain=target,
        registrar=registrar,
        abuse_contact=abuse_to,
        subject="Phishing abuse report - %s - case %s" %
        (target or "domain",
         case.case_number),
        body=body,
        sent=False,
    )


# ---------------------------------------------------------------------------
# SLA
# ---------------------------------------------------------------------------


def start_sla(target_minutes: Optional[int] = None) -> SlaState:
    minutes = int(
        target_minutes if target_minutes is not None else get_settings().sla_minutes)
    started = datetime.now(timezone.utc)
    return SlaState(
        started_at=started.isoformat(),
        target_minutes=minutes,
        deadline_at=(
            started +
            timedelta(
                minutes=minutes)).isoformat(),
        remaining_seconds=minutes *
        60.0)


def sla_state(sla: SlaState, now: Optional[datetime] = None) -> SlaState:
    """Recompute elapsed/remaining. Pure function of the stored timestamps, so a
    restart cannot reset the clock."""
    now = now or datetime.now(timezone.utc)
    started = _parse_iso(sla.started_at) or now
    end = _parse_iso(sla.closed_at) if sla.closed_at else now
    end = end or now
    sla.elapsed_seconds = round((end - started).total_seconds(), 1)
    deadline = _parse_iso(
        sla.deadline_at) or (
        started +
        timedelta(
            minutes=sla.target_minutes))
    sla.remaining_seconds = round((deadline - end).total_seconds(), 1)
    sla.breached = sla.remaining_seconds < 0
    return sla


def close_sla(sla: SlaState, now: Optional[datetime] = None) -> SlaState:
    now = now or datetime.now(timezone.utc)
    sla.closed_at = now.isoformat()
    return sla_state(sla, now)


# ---------------------------------------------------------------------------
# human-in-the-loop
# ---------------------------------------------------------------------------

DECISIONS = ("approve", "override", "escalate")


def record_decision(case: Case, decision: str, analyst: str, note: str = "",
                    override_verdict: str = "") -> Case:
    """Apply an analyst decision to the case.

    Nothing in MailTrace quarantines, blocks or notifies on its own: the verdict
    produces a *recommendation*, and this is the gate that turns it into a
    decision. The decision is also what gets hash-chained, because "who approved
    this" is the question an audit asks first.
    """
    if decision not in DECISIONS:
        raise ValueError("decision must be one of %s" % (DECISIONS,))
    if not analyst.strip():
        raise ValueError(
            "an analyst identity is required: an unattributed decision "
            "is not an audit trail")
    case.action.recommended_action = case.verdict.recommended_action
    case.action.analyst = analyst.strip()
    case.action.analyst_note = note.strip()[:1000]
    case.action.decided_at = utcnow()
    case.verdict.requires_human_review = False
    if decision == "approve":
        case.action.status = STATUS_APPROVED
        case.status = STATUS_APPROVED
    elif decision == "escalate":
        case.action.status = STATUS_ESCALATED
        case.status = STATUS_ESCALATED
    else:
        if not override_verdict:
            raise ValueError("an override must state the replacement verdict")
        case.action.status = STATUS_OVERRIDDEN
        case.action.override_verdict = override_verdict
        case.status = STATUS_OVERRIDDEN
        # The original machine verdict is kept verbatim in the rationale: an
        # override that erases what the system said destroys the audit trail.
        case.verdict.rationale = (
            "analyst override to %r by %s; original machine verdict "
            "%r at risk %.1f. Original rationale: %s" %
            (override_verdict,
             analyst,
             case.verdict.label,
             case.verdict.risk_score,
             case.verdict.rationale))
        case.verdict.label = override_verdict
    case.sla = close_sla(case.sla)
    case.updated_at = utcnow()
    return case


def next_actions(case: Case) -> List[Dict[str, str]]:
    """Concrete containment steps, derived from what the case actually found.

    Generic advice ("investigate further") is filler; these are keyed to the
    evidence so the analyst can work down the list.
    """
    out: List[Dict[str, str]] = []
    v = case.verdict
    radius = case.blast_radius
    p = case.parsed_email
    if v.label in (VERDICT_PHISHING, VERDICT_SUSPICIOUS):
        out.append(
            {
                "action": "Quarantine estate-wide",
                "detail": "purge by Message-ID %s and by raw SHA-256 %s" %
                (p.message_id or "(absent)",
                 (p.raw_sha256 or "")[
                     :16]),
                "urgency": "immediate"})
    if radius.total_credentials_submitted:
        out.append({"action": "Force password reset and revoke sessions",
                    "detail": "%d recipient(s) submitted credentials"
                              % radius.total_credentials_submitted,
                    "urgency": "immediate"})
    elif radius.total_clicked:
        out.append({"action": "Reset credentials for users who clicked",
                    "detail": "%d click(s) recorded" % radius.total_clicked,
                    "urgency": "immediate"})
    hosts = sorted(
        {u.registrable_domain for u in p.urls if u.registrable_domain})
    if hosts:
        out.append({"action": "Block link domains at the proxy and DNS",
                    "detail": ", ".join(hosts[:6]), "urgency": "today"})
    origin_ips = [h.ip for h in case.relay_hops[:1] if h.ip]
    if origin_ips:
        out.append({"action": "Block the origin IP at the mail gateway",
                    "detail": ", ".join(origin_ips), "urgency": "today"})
    if case.attribution.actor_type == ACTOR_COMPROMISED:
        out.append(
            {
                "action": "Notify the sending organisation of a suspected account compromise",
                "detail": "authentication aligned for %s, so the mailbox itself is likely "
                "in attacker hands" %
                p.from_domain,
                "urgency": "today"})
    if case.attribution.actor_type == ACTOR_SPOOFED and p.from_domain:
        out.append({"action": "Raise DMARC enforcement / add a spoofing rule",
                    "detail": "inbound mail claiming %s failed alignment" % p.from_domain,
                    "urgency": "this week"})
    if case.verdict.threat_class == THREAT_FRAUD:
        out.append(
            {
                "action": "Freeze and re-verify the payment instruction out of band",
                "detail": "call the known-good number on file; do not reply to the thread",
                "urgency": "immediate"})
    out.append({"action": "Preserve evidence",
                "detail": "custody chain head %s; retention %d days"
                          % ((case.chain_receipts[-1].tx_hash[:18] + "...")
                             if case.chain_receipts else "not recorded",
                             get_settings().retention_days),
                "urgency": "record"})
    return out
