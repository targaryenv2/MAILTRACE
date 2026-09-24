"""MITRE ATT&CK mapping for the signals MailTrace raises.

Why a static table instead of a lookup service: the mapping from "we saw a
double file extension" to T1036.007 is an analyst judgement, not a query. It
should be reviewable in source, identical on every machine, and available with
no network. So the mapping lives here, and the *names* can optionally be
refreshed from a real ATT&CK STIX bundle if one has been downloaded to
``data/mitre/enterprise-attack.json`` (see ``scripts/fetch_datasets.py``) - the
bundle is used to verify and update titles, never to invent mappings.

Only techniques genuinely evidenced by email artefacts are mapped. Padding a
report with speculative techniques (T1055 process injection because there was
an attachment) is how ATT&CK mapping loses credibility with a real SOC.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..config import DATA_DIR
from ..schemas import Signal

log = logging.getLogger(__name__)

_INDEX_RE = re.compile(r"\.\d+$")

# technique id -> (name, tactic)
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1566.003": ("Phishing: Spearphishing via Service", "Initial Access"),
    "T1598": ("Phishing for Information", "Reconnaissance"),
    "T1598.002": ("Phishing for Information: Spearphishing Attachment", "Reconnaissance"),
    "T1598.003": ("Phishing for Information: Spearphishing Link", "Reconnaissance"),
    "T1656": ("Impersonation", "Defense Evasion"),
    "T1585.002": ("Establish Accounts: Email Accounts", "Resource Development"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
    "T1583.006": ("Acquire Infrastructure: Web Services", "Resource Development"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1586.002": ("Compromise Accounts: Email Accounts", "Resource Development"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", "Defense Evasion"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1137": ("Office Application Startup", "Persistence"),
    "T1090.003": ("Proxy: Multi-hop Proxy", "Command and Control"),
    "T1102": ("Web Service", "Command and Control"),
    "T1534": ("Internal Spearphishing", "Lateral Movement"),
    "T1114": ("Email Collection", "Collection"),
    "T1056.003": ("Input Capture: Web Portal Capture", "Collection"),
    "T1657": ("Financial Theft", "Impact"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
}

# ATT&CK tactic order, so a report reads left-to-right along the kill chain
# instead of in dictionary order.
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Signal id (index suffix stripped) -> techniques it evidences.
SIGNAL_MAP: Dict[str, Tuple[str, ...]] = {
    # authentication and spoofing
    "auth.spf_fail": ("T1566", "T1656"),
    "auth.spf_unaligned": ("T1656", "T1036.005"),
    "auth.dkim_fail": ("T1566", "T1656"),
    "auth.dmarc_fail": ("T1566", "T1656"),
    "auth.no_auth": ("T1566",),
    "auth.arc_fail": ("T1566",),
    # identity
    "id.brand_impersonation": ("T1656", "T1036.005"),
    "id.lookalike_domain": ("T1583.001", "T1036.005"),
    "id.confusable_chars": ("T1036", "T1583.001"),
    "id.punycode_sender": ("T1036", "T1583.001"),
    "id.name_contains_other_address": ("T1656", "T1036"),
    "id.replyto_divergence": ("T1585.002", "T1656"),
    "id.returnpath_mismatch": ("T1656",),
    "id.suspicious_tld": ("T1583.001",),
    # language / social engineering
    "nlp.urgency": ("T1566",),
    "nlp.credential_lure": ("T1598.003", "T1056.003"),
    "nlp.payment_diversion": ("T1657", "T1566"),
    "nlp.authority_pressure": ("T1656", "T1657"),
    "nlp.secrecy": ("T1657",),
    "nlp.bec_no_payload": ("T1656", "T1657", "T1534"),
    "nlp.shouting_subject": ("T1566",),
    "nlp.hidden_text": ("T1027",),
    "nlp.image_only": ("T1027",),
    "nlp.possible_quishing": ("T1566.002", "T1204.001"),
    # links
    "url.ip_literal": ("T1566.002", "T1583.006"),
    "url.anchor_mismatch": ("T1566.002", "T1036"),
    "url.punycode": ("T1566.002", "T1036"),
    "url.shortener": ("T1566.002", "T1102"),
    "url.lookalike": ("T1566.002", "T1583.001"),
    "url.credential_path": ("T1566.002", "T1056.003", "T1204.001"),
    "url.bad_tld": ("T1583.001",),
    "url.many": ("T1566.002",),
    # attachments
    "att.executable": ("T1566.001", "T1204.002"),
    "att.double_ext": ("T1036.007", "T1204.002"),
    "att.type_mismatch": ("T1036", "T1027"),
    "att.macro": ("T1566.001", "T1137", "T1059"),
    "att.archive": ("T1027", "T1566.001"),
    # headers and relay
    "hdr.no_message_id": ("T1566",),
    "hdr.message_id_mismatch": ("T1036",),
    "hdr.no_received": ("T1027",),
    "hdr.undisclosed_recipients": ("T1566",),
    "hdr.mass_recipients": ("T1566",),
    "hdr.bulk_mailer": ("T1566",),
    "relay.multi_country": ("T1090.003",),
    "relay.forged_timestamp": ("T1070", "T1090.003"),
    "relay.chain_manipulation": ("T1090.003",),
    # enrichment-derived
    "intel.tor_exit": ("T1090.003",),
    "intel.abuse_reports": ("T1583.006",),
    "intel.new_domain": ("T1583.001",),
    "intel.blacklisted": ("T1583.006",),
    "intel.no_mx": ("T1583.001",),
    "sandbox.credential_form": ("T1056.003", "T1204.001"),
    "sandbox.redirect_chain": ("T1027", "T1204.001"),
    "sandbox.brand_clone": ("T1656", "T1036.005"),
    "ml.score": (),  # a model score is not itself an adversary technique
}

_bundle_cache: Optional[Dict[str, Tuple[str, str]]] = None


def _bundle() -> Dict[str, Tuple[str, str]]:
    """Load names/tactics from a downloaded ATT&CK STIX bundle if present.

    Returns an empty dict when the bundle is absent, which is the normal case -
    the built-in table is authoritative either way.
    """
    global _bundle_cache
    if _bundle_cache is not None:
        return _bundle_cache
    _bundle_cache = {}
    path = DATA_DIR / "mitre" / "enterprise-attack.json"
    if not path.exists():
        return _bundle_cache
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        for obj in raw.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue
            tid = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    break
            if not tid:
                continue
            phases = obj.get("kill_chain_phases") or []
            tactic = ""
            if phases:
                tactic = phases[0].get(
                    "phase_name", "").replace(
                    "-", " ").title()
            _bundle_cache[tid] = (obj.get("name", ""), tactic)
        log.info("loaded %d ATT&CK techniques from bundle", len(_bundle_cache))
    except (OSError, ValueError) as exc:
        log.warning("ATT&CK bundle unreadable (%s); using built-in table", exc)
    return _bundle_cache


def describe(technique_id: str) -> Tuple[str, str, str]:
    """(name, tactic, source) for a technique id."""
    live = _bundle().get(technique_id)
    if live and live[0]:
        return live[0], live[1] or TECHNIQUES.get(
            technique_id, ("", ""))[1], "attack-bundle"
    name, tactic = TECHNIQUES.get(technique_id, ("", ""))
    return name, tactic, "built-in-table"


def base_id(signal_id: str) -> str:
    """``url.anchor_mismatch.3`` -> ``url.anchor_mismatch``."""
    return _INDEX_RE.sub("", signal_id)


def techniques_for_signal(signal_id: str) -> Tuple[str, ...]:
    return SIGNAL_MAP.get(base_id(signal_id), ())


def enrich_signals(signals: Iterable[Signal]) -> List[Signal]:
    """Stamp the primary technique onto each triggered signal, in place.

    The primary technique is the first in the mapping tuple, ordered most
    specific first, so the queue column shows T1566.002 rather than T1566.
    """
    out: List[Signal] = []
    for sig in signals:
        ids = techniques_for_signal(sig.id)
        if ids and sig.triggered:
            name, tactic, _ = describe(ids[0])
            sig.mitre_technique = ids[0]
            sig.mitre_technique_name = name
            sig.mitre_tactic = tactic
        out.append(sig)
    return out


def techniques_for_case(signals: Iterable[Signal],
                        extra: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Aggregate the case's techniques, each with the signals that evidence it.

    Sorted along the ATT&CK kill chain, then by technique id, so two runs of the
    same case produce byte-identical report sections.
    """
    hits: Dict[str, List[str]] = {}
    for sig in signals:
        if not sig.triggered:
            continue
        for tid in techniques_for_signal(sig.id):
            hits.setdefault(tid, [])
            if sig.title not in hits[tid]:
                hits[tid].append(sig.title)
    for tid in extra or ():
        hits.setdefault(tid, ["manually mapped"])

    rows: List[Dict[str, Any]] = []
    for tid, evidence in hits.items():
        name, tactic, src = describe(tid)
        rows.append({
            "technique": tid,
            "name": name or tid,
            "tactic": tactic or "Unknown",
            "url": "https://attack.mitre.org/techniques/%s/" % tid.replace(".", "/"),
            "evidence": evidence[:6],
            "evidence_count": len(evidence),
            "source": src,
        })
    rows.sort(
        key=lambda r: (
            TACTIC_ORDER.index(
                r["tactic"]) if r["tactic"] in TACTIC_ORDER else len(TACTIC_ORDER),
            r["technique"]))
    return rows


def coverage() -> Dict[str, Any]:
    """Self-check used by the tests and the capability panel: every technique
    referenced by the signal map must exist in the table, or a report would
    render a blank technique name."""
    referenced = {t for ids in SIGNAL_MAP.values() for t in ids}
    missing = sorted(t for t in referenced if t not in TECHNIQUES)
    return {
        "signals_mapped": len([k for k, v in SIGNAL_MAP.items() if v]),
        "techniques_referenced": len(referenced),
        "techniques_known": len(TECHNIQUES),
        "missing_from_table": missing,
        "bundle_loaded": bool(_bundle()),
        "tactics": sorted({TECHNIQUES[t][1] for t in referenced if t in TECHNIQUES}),
    }
