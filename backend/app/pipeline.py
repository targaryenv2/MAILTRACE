"""The one entry point everything else calls: raw bytes in, saved Case out.

The API, the CLI and the test suite all route through :func:`ingest_bytes`, so
there is exactly one definition of "what MailTrace does to an email". Anything
that only the web UI did would rot; anything only the CLI did would never be
demoed.

Order matters and is deliberate:

1. **Parse** - fail closed. A message that cannot be parsed still produces a case
   with the error recorded, because "the analyser crashed on it" is itself a
   finding worth keeping.
2. **Deduplicate before investigating.** Hash the raw bytes first; if this exact
   message was already processed, return the stored case instead of spending
   threat-intel quota on it again.
3. **Investigate** (:mod:`app.agent.loop`) with the existing case corpus in hand,
   so correlation and campaign grouping see history.
4. **Narrate, persist, then anchor.** The custody receipt is written last and
   covers the final verdict, so the hash on chain is the hash of what the analyst
   actually reads.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .alerts.notifier import dispatch_alert
from .agent.loop import investigate
from .agent.narrative import attach_narrative
from .blockchain import get_chain
from .config import DEMO_DIR, get_settings
from .graph.correlate import extract_iocs
from .ingestion.parser import parse_eml, sha256_hex
from .privacy.redact import mask_text, safe_log_fields
from .schemas import (STATUS_AWAITING_APPROVAL, STATUS_CLEARED, STATUS_FAILED,
                      Case, ParsedEmail, utcnow)
from .store import get_store
from .workflow.triage import export_iocs, next_actions, start_sla, takedown_draft

log = logging.getLogger(__name__)



def new_case_id() -> str:
    return "case_%s" % uuid.uuid4().hex[:16]


def build_case(
        raw: bytes,
        filename: str = "",
        source: str = "upload",
        reported_by: str = "",
        case_number: Optional[str] = None) -> Case:
    """Parse ``raw`` into a Case skeleton. Never raises on malformed input."""
    store = get_store()
    case = Case(id=new_case_id(),
                case_number=case_number or store.next_case_number(),
                source=source, reported_by=reported_by,
                filename=filename or "message.eml")
    case.email_hash = sha256_hex(raw)
    try:
        parsed = parse_eml(raw, filename=filename)
    except Exception as exc:  # noqa: BLE001 - a broken email must not break the queue
        log.exception("parse failed for %s", filename)
        case.parsed_email = ParsedEmail()
        case.errors.append("parse failed: %s" % str(exc)[:200])
        case.status = STATUS_FAILED
        return case
    case.parsed_email = parsed
    case.subject = parsed.subject
    case.sender_display = parsed.from_name
    case.sender_address = parsed.from_address
    case.recipient = (parsed.to or [""])[0]
    case.errors.extend(parsed.parse_errors or [])
    case.sla = start_sla()
    return case


def find_duplicate(email_hash: str) -> Optional[Case]:
    """Byte-identical resubmission of a message already on file."""
    return get_store().find_by_hash(email_hash)


def ingest_bytes(raw: bytes,
                 filename: str = "",
                 source: str = "upload",
                 reported_by: str = "",
                 on_step: Optional[Callable[[Any],
                                            None]] = None,
                 anchor: bool = True,
                 reuse_duplicates: bool = True) -> Case:
    """Full pipeline. Returns the saved case."""
    started = time.time()
    store = get_store()
    email_hash = sha256_hex(raw)

    if reuse_duplicates:
        prior = find_duplicate(email_hash)
        if prior is not None:
            updated = reinvestigate(prior.id, anchor=anchor) or prior
            dispatch_alert(updated)
            store.log_event(
                updated.id,
                "duplicate_submission",
                "system",
                "identical message re-submitted as %s" %
                (filename or "upload"))
            log.info("duplicate submission of %s returned case %s (alert dispatched)",
                     email_hash[:12], updated.case_number)
            return updated


    case = build_case(
        raw,
        filename=filename,
        source=source,
        reported_by=reported_by)
    if case.status == STATUS_FAILED:
        store.save(case)
        store.log_event(case.id, "ingest_failed", "system",
                        "; ".join(case.errors[:3]))
        return case

    existing = store.all_cases(limit=300)
    chain = get_chain() if anchor else None
    try:
        case = investigate(
            case,
            existing=existing,
            chain=chain,
            on_step=on_step)
    except Exception as exc:  # noqa: BLE001 - partial results beat a lost case
        log.exception("investigation failed for %s", case.case_number)
        case.errors.append("investigation aborted: %s" % str(exc)[:200])
        case.status = STATUS_FAILED

    case = attach_narrative(case)
    if not case.iocs:
        case.iocs = extract_iocs(case)
    case.takedown = takedown_draft(case)
    case.updated_at = utcnow()
    if case.status != STATUS_FAILED:
        # The loop already chose awaiting_approval vs cleared from the verdict; only
        # fill it in if something went wrong and left the case mid-flight.
        if case.status not in (STATUS_AWAITING_APPROVAL, STATUS_CLEARED):
            case.status = (
                STATUS_AWAITING_APPROVAL if case.verdict.requires_human_review else STATUS_CLEARED)
        case.completed_at = case.completed_at or utcnow()

    store.save(case)
    dispatch_alert(case)
    store.log_event(case.id, "investigation_complete", "system",
                    "%s / risk %.1f / %.0f%% confidence in %.2fs"
                    % (case.verdict.label, case.verdict.risk_score,
                       case.verdict.confidence, time.time() - started))
    log.info(
        "case %s", safe_log_fields(
            case.case_number, verdict=case.verdict.label, risk=round(
                case.verdict.risk_score, 1), seconds=round(
                time.time() - started, 2)))
    return case


def ingest_file(path: str, **kwargs: Any) -> Case:
    p = Path(path)
    return ingest_bytes(p.read_bytes(), filename=p.name, **kwargs)


def ingest_directory(directory: str, pattern: str = "*.eml", limit: int = 0,
                     **kwargs: Any) -> List[Case]:
    """Batch ingest, sorted by filename so a demo run is reproducible.

    Cases are processed sequentially on purpose: each investigation correlates
    against the ones already stored, and running them in parallel would make the
    campaign grouping depend on thread scheduling.
    """
    paths = sorted(Path(directory).glob(pattern))
    if limit:
        paths = paths[:limit]
    out: List[Case] = []
    for p in paths:
        try:
            out.append(ingest_file(str(p), **kwargs))
        except OSError as exc:
            log.warning("could not read %s: %s", p.name, exc)
    return out


def reinvestigate(case_id: str, anchor: bool = True) -> Optional[Case]:
    """Re-run analysis on a stored case, e.g. after adding API keys.

    The original case is replaced, but the custody chain keeps both runs, so the
    change in verdict is auditable rather than silent.
    """
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return None
    before = (case.verdict.label, round(case.verdict.risk_score, 1))
    case.trail = []
    case.signals = []
    case.intel = []
    case.sandbox = []
    others = [c for c in store.all_cases(limit=300) if c.id != case.id]
    case = investigate(
        case,
        existing=others,
        chain=get_chain() if anchor else None)
    case = attach_narrative(case)
    case.updated_at = utcnow()
    store.save(case)
    dispatch_alert(case)
    store.log_event(
        case.id,
        "reinvestigated",
        "system",
        "%s %.1f -> %s %.1f" %
        (before[0],
         before[1],
         case.verdict.label,
         case.verdict.risk_score))
    return case


def case_bundle(case_id: str) -> Optional[Dict[str, Any]]:
    """Everything the investigator screen needs, in one response.

    The UI would otherwise make six round trips to render one case, and the
    derived pieces (next actions, STIX export, custody verification) are cheap to
    compute but fiddly to keep consistent across separate endpoints.
    """
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return None
    chain = get_chain()
    return {
        "case": case.to_dict(),
        "summary": case.summary(),
        "next_actions": next_actions(case),
        "audit": store.audit_trail(case.id, limit=50),
        "related": [store.get(cid).summary() for cid in case.attribution.related_case_ids[:10]
                    if store.get(cid) is not None],
        "exports": {"stix": export_iocs(case, "stix"), "misp": export_iocs(case, "misp")},
        "chain": chain.verify_local(case.case_number) if chain else {},
    }


def seed_demo(directory: Optional[str] = None, limit: int = 0,
              include_wave: bool = True) -> Dict[str, Any]:
    """Load the bundled demo emails. Idempotent: re-running reuses stored cases.

    The wave sub-directory is loaded second and on purpose. The seven top-level
    demo emails are each a different attack family, which is what the detection
    and forensics screens need; ``wave/`` is one campaign re-addressed to six
    people at one company, which is what the campaign roll-up and blast-radius
    screens need. Without it every case is a campaign of one and those two
    features look broken rather than idle.
    """
    st = get_settings()
    st.ensure_dirs()
    target = directory or str(DEMO_DIR)
    cases = ingest_directory(target, limit=limit)
    wave_dir = Path(target) / "wave"
    if include_wave and not limit and wave_dir.is_dir():
        cases += ingest_directory(str(wave_dir))
    store = get_store()
    return {
        "ingested": len(cases),
        "directory": target,
        "cases": [c.summary() for c in cases],
        "stats": store.stats(),
        "campaigns": store.campaigns(limit=10),
    }
