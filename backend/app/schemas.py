"""Shared data contract for the whole MailTrace pipeline.

Everything that crosses a module boundary — parser to detector, detector to
agent, agent to report, backend to frontend — is one of these dataclasses.
Keeping the contract in one file is what stops the six subsystems from
drifting apart.

Conventions used throughout:

* **Timestamps are ISO-8601 UTC strings**, never ``datetime`` objects. They
  cross a JSON boundary constantly and a string that is already correct beats
  a serialiser that has to be remembered.
* **Every enrichment result carries a ``source``** — ``live``, ``fixture``,
  ``offline-table``, ``unavailable``. A forensic tool has to be able to say
  where a value came from, and the UI badges it.
* **Nothing is invented.** Where a lookup fails the field stays ``None`` and
  ``source`` says ``unavailable``; we do not substitute a plausible value.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any, Dict, List, Optional, Union, get_args, get_origin, get_type_hints,
)

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

# Risk bands. Ordered low -> high; ``clean`` is a distinct band from ``low``
# because "we found nothing" and "we found something minor" are different
# statements to put in front of an analyst.
RISK_CLEAN = "clean"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"
RISK_LEVELS = (RISK_CLEAN, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL)

# Case lifecycle.
STATUS_QUEUED = "queued"
STATUS_ANALYZING = "analyzing"
STATUS_AWAITING_APPROVAL = "awaiting_approval"
STATUS_APPROVED = "approved"
STATUS_OVERRIDDEN = "overridden"
STATUS_CLEARED = "cleared"
STATUS_ESCALATED = "escalated"
STATUS_MERGED = "merged"
STATUS_FAILED = "failed"
CASE_STATUSES = (
    STATUS_QUEUED,
    STATUS_ANALYZING,
    STATUS_AWAITING_APPROVAL,
    STATUS_APPROVED,
    STATUS_OVERRIDDEN,
    STATUS_CLEARED,
    STATUS_ESCALATED,
    STATUS_MERGED,
    STATUS_FAILED,
)

# Verdicts are deliberately coarser than the risk score. A number implies
# more precision than a phishing classifier has.
VERDICT_PHISHING = "phishing"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BEC = "bec"
VERDICT_MALWARE = "malware"
VERDICT_LIKELY_BENIGN = "likely_benign"
VERDICT_BENIGN = "benign"
VERDICT_INDETERMINATE = "indeterminate"
VERDICTS = (
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    VERDICT_BEC,
    VERDICT_MALWARE,
    VERDICT_LIKELY_BENIGN,
    VERDICT_BENIGN,
    VERDICT_INDETERMINATE,
)


# Provenance of any enriched value.
SOURCE_LIVE = "live"
SOURCE_FIXTURE = "fixture"
SOURCE_OFFLINE_TABLE = "offline-table"
SOURCE_UNAVAILABLE = "unavailable"
SOURCE_COMPUTED = "computed"
SOURCE_SIMULATED = "simulated"

# PS-26106 asks for classification into these five buckets. They are a
# *different question* from the risk verdict: `label` says how confident we are
# that the mail is malicious, `threat_class` says what kind of malicious it is.
THREAT_LEGITIMATE = "legitimate"
THREAT_SUSPICIOUS = "suspicious"
THREAT_IMPERSONATED = "impersonated"
THREAT_PHISHING = "phishing"
THREAT_FRAUD = "fraud"
THREAT_CLASSES = (THREAT_LEGITIMATE, THREAT_SUSPICIOUS, THREAT_IMPERSONATED,
                  THREAT_PHISHING, THREAT_FRAUD)

# Attribution hypotheses. The brief is explicit that "who sent it" has more than
# one shape, and conflating them misdirects the response: a compromised account
# needs a password reset, a spoofed domain needs DMARC enforcement.
ACTOR_COMPROMISED = "compromised-account"
ACTOR_SPOOFED = "spoofed-domain"
ACTOR_ANONYMISED = "anonymised-infrastructure"
ACTOR_DIRECT = "direct-actor"
ACTOR_UNKNOWN = "insufficient-evidence"

STEP_OK = "ok"
STEP_FAILED = "failed"
STEP_SKIPPED = "skipped"


def utcnow() -> str:
    """Current time as an ISO-8601 UTC string with a ``Z`` suffix."""
    return datetime.now(
        timezone.utc).isoformat(
        timespec="milliseconds").replace(
            "+00:00",
        "Z")


def _clean(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _clean(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return value


class Serialisable:
    """Mixin giving every schema object a JSON-ready ``to_dict`` and the inverse.

    ``from_dict`` exists because a case has to survive a round trip through SQLite
    and the HTTP API: correlation, report rendering and the analyst decision path
    all operate on rebuilt :class:`Case` objects, and rebuilding them by hand
    would drift from the schema the moment a field is added. Unknown keys are
    ignored rather than raising, so an older stored case still loads after a new
    field is introduced.
    """

    def to_dict(self) -> Dict[str, Any]:
        return {k: _clean(v) for k, v in dataclasses.asdict(
            self).items()}  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Any:
        if not isinstance(data, dict):
            raise TypeError("%s.from_dict expects a dict, got %s"
                            % (cls.__name__, type(data).__name__))
        # type: ignore[arg-type]
        names = {f.name for f in dataclasses.fields(cls)}
        hints = _hints(cls)
        kwargs = {k: _coerce(hints.get(k), v)
                  for k, v in data.items() if k in names}
        return cls(**kwargs)  # type: ignore[call-arg]

    def __getitem__(self, key: str) -> Any:
        if key == "org" and hasattr(self, "isp"):
            return getattr(self, "isp")
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default




_HINTS: Dict[type, Dict[str, Any]] = {}


def _hints(cls: type) -> Dict[str, Any]:
    """Resolved type hints, cached. ``from __future__ import annotations`` makes
    every annotation a string, so they have to be resolved at runtime."""
    if cls not in _HINTS:
        try:
            _HINTS[cls] = get_type_hints(cls, globalns=globals())
        except Exception:  # pragma: no cover - defensive
            _HINTS[cls] = {}
    return _HINTS[cls]


def _coerce(hint: Any, value: Any) -> Any:
    """Rebuild nested dataclasses from plain JSON values."""
    if value is None or hint is None:
        return value
    origin = get_origin(hint)
    if origin is Union:  # Optional[X] and friends
        inner = [a for a in get_args(hint) if a is not type(None)]
        return _coerce(inner[0], value) if inner else value
    if origin in (list, List):
        args = get_args(hint)
        return [_coerce(args[0] if args else None, v) for v in value]
    if origin in (dict, Dict):
        return value
    if dataclasses.is_dataclass(hint) and isinstance(value, dict):
        return hint.from_dict(value)  # type: ignore[attr-defined]
    return value


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------


@dataclass
class Attachment(Serialisable):
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    # Detected from magic bytes where possible, so a ".pdf" that is really a
    # PE executable is caught rather than trusted.
    detected_type: str = "unknown"
    extension_mismatch: bool = False
    is_archive: bool = False
    is_macro_capable: bool = False
    is_executable: bool = False
    double_extension: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class ExtractedUrl(Serialisable):
    url: str
    domain: str
    scheme: str = ""
    path: str = ""
    # Where in the message the URL was found; anchor-text mismatch is only
    # meaningful for HTML links.
    location: str = "body_text"  # body_text | body_html | anchor | header
    anchor_text: str = ""
    anchor_mismatch: bool = False
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    registrable_domain: str = ""
    tld: str = ""
    reasons: List[str] = field(default_factory=list)


@dataclass
class AuthResult(Serialisable):
    """SPF/DKIM/DMARC outcome plus the alignment checks that actually matter.

    A pass on its own means little: SPF can pass for an attacker-controlled
    envelope domain while the visible From is spoofed. ``spf_aligned`` /
    ``dkim_aligned`` capture RFC 7489 identifier alignment, which is the part
    that decides whether DMARC passes.
    """

    # pass | fail | softfail | neutral | none | temperror | permerror | unknown
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_policy: str = ""
    from_domain: str = ""
    envelope_from_domain: str = ""
    spf_aligned: Optional[bool] = None
    dkim_aligned: Optional[bool] = None
    arc_chain: str = "none"  # none | pass | fail
    raw_headers: List[str] = field(default_factory=list)
    source: str = SOURCE_COMPUTED
    parse_notes: List[str] = field(default_factory=list)


@dataclass
class ParsedEmail(Serialisable):
    message_id: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    subject: str = ""
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    urls: List[ExtractedUrl] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    headers: List[Dict[str, str]] = field(default_factory=list)
    received_chain: List["ReceivedHeader"] = field(default_factory=list)
    auth: AuthResult = field(default_factory=AuthResult)
    raw_sha256: str = ""
    size_bytes: int = 0
    # A malformed message must degrade, not explode: partial results plus a
    # list of what could not be read.
    parse_complete: bool = True
    parse_errors: List[str] = field(default_factory=list)
    x_headers: Dict[str, str] = field(default_factory=dict)
    has_qr_code: bool = False
    qr_payloads: List[str] = field(default_factory=list)


@dataclass
class ReceivedHeader(Serialisable):
    """One parsed ``Received:`` header, before geolocation."""

    index: int
    raw: str
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    protocol: str = ""
    timestamp: str = ""
    is_private_ip: bool = False
    parse_ok: bool = True


# --------------------------------------------------------------------------
# GeoIP / relay path
# --------------------------------------------------------------------------


@dataclass
class GeoLocation(Serialisable):
    lat: Optional[float] = None
    lon: Optional[float] = None
    city: str = ""
    country: str = ""
    country_code: str = ""
    asn: str = ""
    isp: str = ""
    resolved: bool = False
    source: str = SOURCE_UNAVAILABLE


@dataclass
class RelayHop(Serialisable):
    index: int
    ip: str
    hostname: str = ""
    timestamp: str = ""
    delay_seconds: Optional[float] = None
    location: GeoLocation = field(default_factory=GeoLocation)
    is_private: bool = False
    is_anomalous: bool = False
    anomaly_reasons: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


@dataclass
class Signal(Serialisable):
    """One detection result. Rules and the ML model both emit these."""

    id: str
    signal_type: str
    title: str
    result: str
    severity: str = RISK_LOW
    weight: float = 0.0
    triggered: bool = True
    # heuristic | authentication | ml | intel | sandbox | relay
    category: str = "heuristic"
    evidence: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    source: str = SOURCE_COMPUTED


@dataclass
class FeatureAttribution(Serialisable):
    """One token's contribution to the ML score.

    For a linear model these are exact Shapley values, not approximations —
    see ``app/ml/explain.py`` for why that identity holds.
    """

    feature: str
    value: float
    contribution: float
    direction: str  # phishing | benign


@dataclass
class MlPrediction(Serialisable):
    probability: Optional[float] = None
    label: str = "unknown"
    model_name: str = "none"
    model_version: str = ""
    threshold: float = 0.5
    top_features: List[FeatureAttribution] = field(default_factory=list)
    base_value: float = 0.0
    available: bool = False
    source: str = SOURCE_UNAVAILABLE
    notes: List[str] = field(default_factory=list)
    probabilities: Dict[str, float] = field(default_factory=dict)
    predicted_class: int = 0
    ai_detector: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Threat intel
# --------------------------------------------------------------------------


@dataclass
class IntelResult(Serialisable):
    provider: str  # abuseipdb | whois | virustotal
    subject: str  # the IP or domain queried
    status: str = "unavailable"  # ok | unavailable | error | rate_limited
    source: str = SOURCE_UNAVAILABLE
    cached: bool = False
    queried_at: str = field(default_factory=utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str = ""


# --------------------------------------------------------------------------
# Sandbox
# --------------------------------------------------------------------------


@dataclass
class RedirectStep(Serialisable):
    url: str
    status: Optional[int] = None
    kind: str = "http"  # http | meta_refresh | javascript


@dataclass
class SandboxResult(Serialisable):
    url: str
    status: str = "skipped"  # detonated | static_only | skipped | error
    verdict: str = "unknown"  # malicious | suspicious | clean | unknown
    final_url: str = ""
    redirect_chain: List[RedirectStep] = field(default_factory=list)
    screenshot_path: str = ""
    page_title: str = ""
    has_password_field: Optional[bool] = None
    form_actions: List[str] = field(default_factory=list)
    detected_brand: str = ""
    indicators: List[str] = field(default_factory=list)
    duration_ms: Optional[int] = None
    source: str = SOURCE_UNAVAILABLE
    notes: str = ""


# --------------------------------------------------------------------------
# Agentic investigation
# --------------------------------------------------------------------------


@dataclass
class TrailStep(Serialisable):
    """One step of the agent's investigation.

    ``reasoning`` is the field that makes this an investigation trail rather
    than a log: it records *why the agent chose this check next*, given what
    the previous step returned.
    """

    index: int
    action: str
    result: str
    reasoning: str = ""
    status: str = STEP_OK
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    duration_ms: Optional[int] = None
    detail: Dict[str, Any] = field(default_factory=dict)
    signals_added: List[str] = field(default_factory=list)
    tx_hash: str = ""
    source: str = SOURCE_COMPUTED


@dataclass
class Verdict(Serialisable):
    """Verdict and confidence are deliberately separate numbers.

    ``risk_score`` answers "how bad does this look"; ``confidence`` answers
    "how much should you trust that". A well-written AI-generated phish scores
    mid-range with low confidence, and that combination is what should route a
    case to a human instead of an auto-action.
    """

    label: str = VERDICT_INDETERMINATE
    threat_class: str = THREAT_SUSPICIOUS
    threat_class_reason: str = ""
    risk_score: float = 0.0
    risk_level: str = RISK_CLEAN
    confidence: float = 0.0
    confidence_band: str = "low"  # low | moderate | high
    ambiguity_flags: List[str] = field(default_factory=list)
    recommended_action: str = ""
    requires_human_review: bool = True
    rationale: str = ""
    narrative: str = ""
    narrative_source: str = "template"
    score_breakdown: Dict[str, float] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Analyst workflow
# --------------------------------------------------------------------------


@dataclass
class ExposureRecord(Serialisable):
    recipient_email: str
    display_name: str = ""
    department: str = ""
    role: str = ""
    delivered: bool = True
    opened: bool = False
    clicked: bool = False
    submitted_credentials: bool = False
    reported: bool = False
    is_high_value: bool = False
    last_event_at: str = ""


@dataclass
class BlastRadius(Serialisable):
    fingerprint: str = ""
    matched_by: List[str] = field(default_factory=list)
    total_recipients: int = 0
    total_opened: int = 0
    total_clicked: int = 0
    total_credentials_submitted: int = 0
    total_reported: int = 0
    high_value_targets: int = 0
    departments_affected: List[str] = field(default_factory=list)
    exposures: List[ExposureRecord] = field(default_factory=list)
    is_campaign: bool = False
    source: str = SOURCE_FIXTURE
    notes: str = ""


@dataclass
class Ioc(Serialisable):
    ioc_type: str  # ipv4-addr | domain-name | url | file-hash | email-addr
    value: str
    context: str = ""
    first_seen: str = field(default_factory=utcnow)
    confidence: int = 50
    exported: bool = False


@dataclass
class CampaignRef(Serialisable):
    id: str = ""
    fingerprint: str = ""
    case_count: int = 1
    first_seen: str = ""
    merged_into: str = ""
    is_duplicate: bool = False
    related_case_ids: List[str] = field(default_factory=list)


@dataclass
class SlaState(Serialisable):
    """Decision-gate timer. Real triage runs against a clock; showing it makes
    the tool read as operational rather than academic."""

    started_at: str = field(default_factory=utcnow)
    target_minutes: int = 20
    deadline_at: str = ""
    closed_at: str = ""
    breached: bool = False
    elapsed_seconds: float = 0.0
    remaining_seconds: float = 0.0


@dataclass
class ActionRecord(Serialisable):
    """Human-in-the-loop gate. Nothing is 'taken' until an analyst says so."""

    recommended_action: str = ""
    status: str = "pending"  # pending | approved | overridden
    analyst: str = ""
    analyst_note: str = ""
    decided_at: str = ""
    override_verdict: str = ""
    tx_hash: str = ""


@dataclass
class TakedownDraft(Serialisable):
    target_domain: str = ""
    registrar: str = ""
    abuse_contact: str = ""
    subject: str = ""
    body: str = ""
    generated_at: str = field(default_factory=utcnow)
    sent: bool = False  # always False: MailTrace drafts, it never sends


# --------------------------------------------------------------------------
# Identity correlation and attribution
# --------------------------------------------------------------------------


@dataclass
class GraphNode(Serialisable):
    id: str
    kind: str  # case | sender | domain | ip | url | asn | attachment | recipient
    label: str = ""
    weight: int = 1
    risk: float = 0.0
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge(Serialisable):
    source: str
    target: str
    kind: str  # sent-by | resolves-to | links-to | shares-asn | same-attachment
    weight: float = 1.0


@dataclass
class Attribution(Serialisable):
    """Confidence-based attribution, deliberately phrased as a hypothesis.

    Forensics does not get to assert identity from headers alone. What the
    evidence *can* support is a ranked hypothesis with its reasons, which is
    what a court-usable report should contain.
    """

    actor_type: str = ACTOR_UNKNOWN
    confidence: float = 0.0
    confidence_band: str = "low"
    reasons: List[str] = field(default_factory=list)
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    infrastructure: List[str] = field(default_factory=list)
    origin_place: str = ""
    origin_precision: str = "unknown"
    cluster_id: str = ""
    cluster_size: int = 1
    related_case_ids: List[str] = field(default_factory=list)
    shared_indicators: List[str] = field(default_factory=list)
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    source: str = SOURCE_COMPUTED
    notes: str = ""


# --------------------------------------------------------------------------
# Blockchain
# --------------------------------------------------------------------------


@dataclass
class ChainReceipt(Serialisable):
    """Result of writing one record to the custody contract.

    ``simulated`` is load-bearing. When no chain is reachable we still produce
    a receipt so the pipeline is testable, but it is flagged everywhere it is
    displayed — an in-process hash is not a blockchain and the report must not
    imply otherwise.
    """

    action: str = ""
    tx_hash: str = ""
    block_number: Optional[int] = None
    chain_id: Optional[int] = None
    contract_address: str = ""
    explorer_url: str = ""
    gas_used: Optional[int] = None
    payload_hash: str = ""
    calldata: str = ""
    simulated: bool = True
    source: str = SOURCE_SIMULATED
    written_at: str = field(default_factory=utcnow)
    error: str = ""


# --------------------------------------------------------------------------
# Case aggregate
# --------------------------------------------------------------------------


@dataclass
class Case(Serialisable):
    id: str
    case_number: str
    status: str = STATUS_QUEUED
    source: str = "upload"  # upload | user_report | mailbox_poll
    reported_by: str = ""
    filename: str = ""
    subject: str = ""
    sender_display: str = ""
    sender_address: str = ""
    recipient: str = ""
    email_hash: str = ""
    fingerprint: str = ""
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)
    completed_at: str = ""

    parsed_email: ParsedEmail = field(default_factory=ParsedEmail)
    signals: List[Signal] = field(default_factory=list)
    ml: MlPrediction = field(default_factory=MlPrediction)
    relay_hops: List[RelayHop] = field(default_factory=list)
    intel: List[IntelResult] = field(default_factory=list)
    trail: List[TrailStep] = field(default_factory=list)
    verdict: Verdict = field(default_factory=Verdict)
    sandbox: List[SandboxResult] = field(default_factory=list)
    blast_radius: BlastRadius = field(default_factory=BlastRadius)
    iocs: List[Ioc] = field(default_factory=list)
    mitre: List[Dict[str, str]] = field(default_factory=list)
    campaign: CampaignRef = field(default_factory=CampaignRef)
    attribution: Attribution = field(default_factory=Attribution)
    origin: Dict[str, Any] = field(default_factory=dict)
    sla: SlaState = field(default_factory=SlaState)
    action: ActionRecord = field(default_factory=ActionRecord)
    takedown: Optional[TakedownDraft] = None
    chain_receipts: List[ChainReceipt] = field(default_factory=list)
    report_path: str = ""
    capabilities: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        """Compact projection for the analyst queue.

        The queue is polled far more often than a case is opened, so it gets a
        deliberately small payload rather than the full evidence blob.
        """
        return {
            "id": self.id,
            "case_number": self.case_number,
            "status": self.status,
            "source": self.source,
            "subject": self.subject,
            "sender_display": self.sender_display,
            "sender_address": self.sender_address,
            "recipient": self.recipient,
            "risk_score": self.verdict.risk_score,
            "risk_level": self.verdict.risk_level,
            "confidence": self.verdict.confidence,
            "confidence_band": self.verdict.confidence_band,
            "verdict": self.verdict.label,
            "threat_class": self.verdict.threat_class,
            "actor_type": self.attribution.actor_type,
            "attribution_confidence": self.attribution.confidence,
            "origin_place": self.attribution.origin_place,
            "requires_human_review": self.verdict.requires_human_review,
            "recommended_action": self.verdict.recommended_action,
            "action_status": self.action.status,
            "signal_count": len([s for s in self.signals if s.triggered]),
            "trail_steps": len(self.trail),
            "exposed_recipients": self.blast_radius.total_recipients,
            "is_campaign": self.blast_radius.is_campaign,
            "campaign_id": self.campaign.id,
            "is_duplicate": self.campaign.is_duplicate,
            "sla": self.sla.to_dict(),
            "tx_hash": self.chain_receipts[-1].tx_hash if self.chain_receipts else "",
            "chain_simulated": self.chain_receipts[-1].simulated if self.chain_receipts else True,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "mitre": [m.get("technique", "") for m in self.mitre],
            "has_report": bool(self.report_path),
        }
