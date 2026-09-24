"""HTTP routes, defined once and served by either framework.

MailTrace has to run on a judge's laptop with no internet and possibly no pip, so
the API cannot *require* FastAPI. It also should not be a worse API just because
FastAPI is absent. The resolution is this module: every endpoint is a plain
function of a :class:`Request` returning a :class:`Response`, with no import of
any web framework. :mod:`app.api.server` serves them on :mod:`http.server` from
the standard library; :mod:`app.api.asgi` mounts the identical table under
FastAPI when it is importable. There is one routing table, so the two cannot
drift, and the tests exercise the table directly without binding a socket.

Design notes worth knowing before editing:

*Errors are values.* A handler returns ``Response.error(404, ...)``; it does not
raise. An unhandled exception is still caught in :func:`dispatch` and turned into
a 500 with the case reference, because a SOC console that goes blank is worse
than one showing a stack-trace id.

*The queue is a projection, a case is a bundle.* ``GET /api/cases`` returns
summaries only (the UI polls it), while ``GET /api/cases/{id}`` returns
everything the investigator screen needs in one round trip. That asymmetry is
deliberate and is why there is no ``?include=`` parameter.

*Nothing here decides anything.* Ingest analyses and recommends; only
``POST /api/cases/{id}/decision`` changes disposition, and it requires an analyst
identity. Automated quarantine is out of scope on purpose - PS-26106 asks for
alerts and evidence, and an autonomous mail-blocking loop is a liability.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

from ..alerts.notifier import send_test_alert
from ..blockchain import get_chain
from ..config import DEMO_DIR, EVIDENCE_DIR, MODEL_DIR, get_settings
from ..graph.correlate import build_graph
from ..pipeline import (
    case_bundle,
    ingest_bytes,
    ingest_directory,
    reinvestigate,
    seed_demo)
from ..privacy.redact import (apply_retention, policy_summary, redact_case,
                              retention_status)
from ..report import build_report, engine_available, map_layout
from ..store import get_store
from ..workflow.triage import (
    DECISIONS,
    export_iocs,
    record_decision,
    sla_state,
    takedown_draft)
from .events import get_bus

log = logging.getLogger(__name__)

# a .eml larger than this is not a mail message
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


# --------------------------------------------------------------------------
# Request / response
# --------------------------------------------------------------------------


@dataclass
class Request:
    method: str
    path: str
    query: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)

    def json(self) -> Dict[str, Any]:
        if not self.body:
            return {}
        try:
            value = json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return value if isinstance(value, dict) else {"value": value}

    def q(self, name: str, default: str = "") -> str:
        return str(self.query.get(name, default) or default)

    def qint(self, name: str, default: int) -> int:
        try:
            return int(str(self.query.get(name, default)))
        except (TypeError, ValueError):
            return default

    def qfloat(
            self,
            name: str,
            default: Optional[float] = None) -> Optional[float]:
        raw = self.query.get(name)
        if raw in (None, ""):
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            return default

    def qbool(self, name: str, default: bool) -> bool:
        raw = str(self.query.get(name, "")).strip().lower()
        if raw in ("1", "true", "yes", "on"):
            return True
        if raw in ("0", "false", "no", "off"):
            return False
        return default

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def ok(cls, data: Any, status: int = 200) -> "Response":
        return cls(status=status,
                   body=json.dumps(data, default=str).encode("utf-8"),
                   content_type="application/json")

    @classmethod
    def error(cls, status: int, message: str, **extra: Any) -> "Response":
        payload = {"error": message, "status": status}
        payload.update(extra)
        return cls.ok(payload, status=status)

    @classmethod
    def raw(cls, data: bytes, content_type: str, filename: str = "",
            download: bool = True) -> "Response":
        headers = {}
        if filename:
            disposition = "attachment" if download else "inline"
            headers["Content-Disposition"] = '%s; filename="%s"' % (
                disposition, filename)
        return cls(
            status=200,
            body=data,
            content_type=content_type,
            headers=headers)

    @classmethod
    def text(cls, data: str, content_type: str = "text/plain; charset=utf-8",
             filename: str = "") -> "Response":
        return cls.raw(data.encode("utf-8"), content_type, filename)


# --------------------------------------------------------------------------
# Upload decoding
# --------------------------------------------------------------------------


def _multipart(body: bytes, boundary: str) -> List[Tuple[str, bytes]]:
    """Split a ``multipart/form-data`` body into ``(filename, content)`` pairs.

    Hand-rolled rather than using :mod:`cgi`, which was removed in Python 3.13:
    depending on it would mean the API works on 3.11 and fails on a newer
    interpreter, which is exactly the portability trap this project is trying to
    avoid. Only what an upload form actually sends is supported.
    """
    marker = ("--" + boundary).encode("latin-1")
    parts: List[Tuple[str, bytes]] = []
    for chunk in body.split(marker):
        if not chunk.strip() or chunk.strip() == b"--":
            continue
        head, _, payload = chunk.partition(b"\r\n\r\n")
        if not payload:
            continue
        header_text = head.decode("latin-1", "replace")
        match = re.search(r'filename="([^"]*)"', header_text)
        name = match.group(1) if match else ""
        if not name:
            field_match = re.search(r'name="([^"]*)"', header_text)
            name = field_match.group(1) if field_match else "upload"
        # Trailing CRLF belongs to the boundary, not the file. Keeping it would
        # change the sha256 of the evidence, which is not a cosmetic error.
        parts.append(
            (name, payload[:-2] if payload.endswith(b"\r\n") else payload))
    return parts


def _uploads(req: Request) -> Tuple[List[Tuple[str, bytes]], str]:
    """Extract ``(filename, raw)`` uploads from any of the shapes a client sends.

    Four are accepted because four are used: a browser ``FormData`` upload, a
    raw ``.eml`` POST from ``curl --data-binary``, a JSON body carrying base64
    (which is what a CORS-restricted fetch tends to do), and a JSON body naming
    a path on disk - the last one only inside the machine's own filesystem,
    which is how the CLI and the demo seeder reuse this endpoint.
    """
    ctype = req.header("content-type")
    if len(req.body) > MAX_UPLOAD_BYTES:
        return [], "upload exceeds %d bytes" % MAX_UPLOAD_BYTES
    if "multipart/form-data" in ctype:
        match = re.search(r"boundary=([^;]+)", ctype)
        if not match:
            return [], "multipart body without a boundary"
        files = [(n, c) for n, c in _multipart(
            req.body, match.group(1).strip('"')) if c]
        return files, "" if files else "multipart body contained no file part"
    if ctype.startswith("application/json"):
        payload = req.json()
        name = str(payload.get("filename") or "upload.eml")
        if payload.get("eml_base64"):
            try:
                return [(name, base64.b64decode(
                    str(payload["eml_base64"]), validate=True))], ""
            except (ValueError, TypeError):
                return [], "eml_base64 is not valid base64"
        if payload.get("raw"):
            return [(name, str(payload["raw"]).encode("utf-8"))], ""
        if payload.get("path"):
            path = Path(str(payload["path"])).expanduser()
            if not path.is_file():
                return [], "no such file: %s" % path
            return [(path.name, path.read_bytes())], ""
        return [], "json body needs one of: eml_base64, raw, path"
    if req.body:
        return [(req.header("x-filename", "upload.eml"), req.body)], ""
    return [], "empty request body"


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def health(req: Request) -> Response:
    st = get_settings()
    store = get_store()
    chain = get_chain()
    return Response.ok({
        "service": "mailtrace",
        "version": "1.0.0",
        "status": "ok",
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "organisation": st.organisation,
        "demo_mode": st.demo_mode,
        "capabilities": st.capability_report(),
        "search_backend": store.search_backend,
        "report_engine": "reportlab" if engine_available() else "minipdf (stdlib)",
        "chain": {"mode": "live" if st.has_chain() else "simulated",
                  "contract": st.contract_address or "",
                  "chain_id": st.chain_id,
                  "explorer": st.chain_explorer_base or ""},
        "counts": store.stats(),
    })


# Only these may be changed at runtime, and each is a knob an analyst has a
# legitimate reason to turn mid-shift. Credentials are absent on purpose: an API
# that can set an API key is an API that can exfiltrate one.
TUNABLE: Dict[str, type] = {
    "conclusive_low": float, "conclusive_high": float, "sla_minutes": int,
    "retention_days": int, "pii_masking": bool, "allow_network": bool,
    "allow_detonation": bool, "demo_mode": bool, "intel_cache_ttl_hours": int,
    "intel_timeout_seconds": float, "organisation": str, "analyst_name": str,
}


def get_config(req: Request) -> Response:
    st = get_settings()
    return Response.ok({
        "settings": {k: getattr(st, k) for k in TUNABLE},
        "editable": {k: v.__name__ for k, v in TUNABLE.items()},
        "capabilities": st.capability_report(),
        "privacy": policy_summary(),
        "notes": [
            "Changes apply to this process only and are not written to .env; the "
            "environment stays the source of truth across restarts.",
            "Threshold changes affect future analysis. Stored cases keep the verdict "
            "they were given - re-run POST /api/cases/{id}/reinvestigate to re-score, "
            "which records both verdicts in the custody trail rather than overwriting.",
        ],
    })


def patch_config(req: Request) -> Response:
    st = get_settings()
    payload = req.json()
    # Snapshot first: a rejected patch has to leave the process exactly as it was.
    # Validating the threshold band after assignment (which is the only way to
    # check the pair) would otherwise half-apply an invalid request.
    before = {k: getattr(st, k) for k in TUNABLE}
    applied: Dict[str, Any] = {}
    rejected: Dict[str, str] = {}
    for key, value in payload.items():
        caster = TUNABLE.get(key)
        if caster is None:
            rejected[key] = "not runtime-editable"
            continue
        try:
            if caster is bool:
                cast: Any = (
                    str(value).strip().lower() in (
                        "1", "true", "yes", "on") if not isinstance(
                        value, bool) else value)
            else:
                cast = caster(value)
        except (TypeError, ValueError):
            rejected[key] = "expected %s" % caster.__name__
            continue
        setattr(st, key, cast)
        applied[key] = cast
    if st.conclusive_low >= st.conclusive_high:
        # Roll the whole patch back and reject: a band where "conclusively safe"
        # sits above "conclusively malicious" would make the agent stop early on
        # everything, and it would look like it was working.
        for key, value in before.items():
            setattr(st, key, value)
        return Response.error(
            400,
            "conclusive_low must stay below conclusive_high",
            rejected_values={
                k: applied[k] for k in (
                    "conclusive_low",
                    "conclusive_high") if k in applied},
            conclusive_low=st.conclusive_low,
            conclusive_high=st.conclusive_high)
    get_bus().publish("config", {"applied": applied})
    return Response.ok({"applied": applied, "rejected": rejected,
                        "settings": {k: getattr(st, k) for k in TUNABLE}})


def stats(req: Request) -> Response:
    return Response.ok(get_store().stats())


def model_card(req: Request) -> Response:
    """Metrics of the deployed classifier, straight from the training report.

    Served from the file the trainer wrote rather than re-stated in code, so the
    number on screen cannot disagree with the number that was measured.
    """
    path = MODEL_DIR / "metrics.json"
    if not path.is_file():
        return Response.error(
            404,
            "no trained model; run scripts/train_model.py",
            expected_at=str(path))
    try:
        return Response.ok(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as exc:
        return Response.error(500, "metrics.json is not valid JSON: %s" % exc)


def ingest(req: Request) -> Response:
    files, problem = _uploads(req)
    if problem:
        return Response.error(400, problem)
    source = req.q("source", "upload")
    reported_by = req.q("reported_by") or req.header("x-analyst")
    anchor = req.qbool("anchor", True)
    bus = get_bus()
    results: List[Dict[str, Any]] = []
    for name, raw in files:
        bus.publish("ingest_start", {"filename": name, "bytes": len(raw)})
        started = time.time()
        case = ingest_bytes(
            raw,
            filename=name,
            source=source,
            reported_by=reported_by,
            anchor=anchor,
            reuse_duplicates=False,
            on_step=bus.step_publisher(name))

        summary = case.summary()
        summary["elapsed_seconds"] = round(time.time() - started, 3)
        results.append(summary)
        bus.publish("case", summary)
    return Response.ok({"count": len(results), "cases": results}, status=201)


def ingest_demo(req: Request) -> Response:
    directory = req.q("directory") or None
    if directory and not Path(directory).is_dir():
        return Response.error(400, "not a directory: %s" % directory)
    bus = get_bus()
    bus.publish("demo_start", {"directory": directory or str(DEMO_DIR)})
    cases = seed_demo(directory=directory, limit=req.qint("limit", 0),
                      include_wave=req.qbool("wave", True))
    bus.publish("demo_complete", {"count": len(cases)})
    return Response.ok({"count": len(cases), "cases": cases}, status=201)


def ingest_path(req: Request) -> Response:
    """Batch-ingest a directory already on this machine.

    Kept separate from ``/api/ingest`` because it takes a path, not a payload:
    conflating them would mean a JSON body that sometimes reads the filesystem
    and sometimes does not, decided by which key the client happened to send.
    """
    payload = req.json()
    directory = str(payload.get("directory") or "")
    if not directory or not Path(directory).is_dir():
        return Response.error(400, "directory is required and must exist")
    bus = get_bus()
    cases = ingest_directory(
        directory,
        pattern=str(
            payload.get("pattern") or "*.eml"),
        limit=int(
            payload.get("limit") or 0))
    summaries = [c.summary() for c in cases]
    for s in summaries:
        bus.publish("case", s)
    return Response.ok(
        {"count": len(summaries), "cases": summaries}, status=201)


def list_cases(req: Request) -> Response:
    store = get_store()
    return Response.ok(store.queue(
        status=req.q("status") or None,
        verdict=req.q("verdict") or None,
        threat_class=req.q("threat_class") or None,
        min_risk=req.qfloat("min_risk"),
        campaign_id=req.q("campaign_id") or None,
        include_duplicates=req.qbool("include_duplicates", True),
        sort=req.q("sort", "created"),
        limit=min(req.qint("limit", 100), 500),
        offset=max(req.qint("offset", 0), 0),
    ))


def get_case(req: Request, case_id: str) -> Response:
    bundle = case_bundle(case_id)
    if bundle is None:
        return Response.error(404, "no such case", case_id=case_id)
    # SLA is a function of wall-clock time, so it is recomputed on read rather
    # than trusted from storage - a stored "12 minutes remaining" is wrong the
    # moment it is written.
    case = get_store().get(case_id)
    if case is not None:
        bundle["case"]["sla"] = sla_state(case.sla).to_dict()
    if req.qbool("mask", get_settings().pii_masking):
        bundle["case"] = redact_case(bundle["case"], deep=True)
        bundle["masked"] = True
    else:
        bundle["masked"] = False
    return Response.ok(bundle)


def case_audit(req: Request, case_id: str) -> Response:
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    return Response.ok({"case_number": case.case_number,
                        "audit": store.audit_trail(case.id, limit=req.qint("limit", 100)),
                        "trail": [s.to_dict() for s in case.trail],
                        "chain_receipts": [r.to_dict() for r in case.chain_receipts]})


def case_graph(req: Request, case_id: str) -> Response:
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    others = [
        c for c in store.all_cases(
            limit=req.qint(
                "scan",
                300)) if c.id != case.id]
    nodes, edges = build_graph(case, others)
    return Response.ok({
        "case_number": case.case_number,
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
        "attribution": case.attribution.to_dict(),
        "note": "Centred on this case. Edges are shared observable artefacts, not "
                "proof of a shared operator.",
    })


def case_map(req: Request, case_id: str) -> Response:
    case = get_store().get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    layout = map_layout(case.relay_hops, case.origin.get("origin_hop_index"))
    layout["origin"] = case.origin
    layout["case_number"] = case.case_number
    return Response.ok(layout)


def case_export(req: Request, case_id: str) -> Response:
    case = get_store().get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    fmt = req.q("fmt", "stix").lower()
    if fmt in ("stix", "misp"):
        payload = export_iocs(case, fmt)
        return Response.raw(
            json.dumps(
                payload,
                indent=2,
                default=str).encode("utf-8"),
            "application/json",
            "%s-iocs-%s.json" %
            (case.case_number,
             fmt))
    if fmt == "csv":
        rows = ["type,value,first_seen,confidence,context"]
        for ioc in case.iocs:
            rows.append(",".join('"%s"' % str(v).replace('"', '""') for v in (
                ioc.ioc_type, ioc.value, ioc.first_seen,
                getattr(ioc, "confidence", ""), getattr(ioc, "context", ""))))
        return Response.text("\n".join(rows) + "\n", "text/csv; charset=utf-8",
                             "%s-iocs.csv" % case.case_number)
    if fmt == "json":
        data = case.to_dict()
        if req.qbool("mask", get_settings().pii_masking):
            data = redact_case(data, deep=True)
        return Response.raw(
            json.dumps(
                data,
                indent=2,
                default=str).encode("utf-8"),
            "application/json",
            "%s-case.json" %
            case.case_number)
    return Response.error(
        400,
        "fmt must be one of: stix, misp, csv, json",
        got=fmt)


def case_takedown(req: Request, case_id: str) -> Response:
    case = get_store().get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    draft = case.takedown or takedown_draft(case)
    if req.q("format") == "text":
        return Response.text(
            draft.body,
            filename="%s-takedown.txt" %
            case.case_number)
    return Response.ok(draft.to_dict())


def case_report(req: Request, case_id: str) -> Response:
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    masking = req.qbool("mask", get_settings().pii_masking)
    engine = req.q("engine") or None
    filename = "%s-forensic-report.pdf" % case.case_number
    reports_dir = EVIDENCE_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    target = reports_dir / filename
    try:
        result = build_report(
            case,
            str(target),
            engine=engine,
            masking=masking)
    except Exception as exc:  # noqa: BLE001 - a failed report must not 500 the console
        log.exception("report generation failed for %s", case.case_number)
        return Response.error(
            500,
            "report generation failed: %s" %
            str(exc)[
                :200])
    store.save(case)
    store.log_event(
        case.id, "report_generated", req.header(
            "x-analyst", "system"), "%d pages via %s, masking %s" %
        (result["pages"], result["engine"], "on" if masking else "off"))
    if req.q("format") == "json" or req.method == "POST":
        return Response.ok(result, status=201)
    return Response.raw(Path(result["path"]).read_bytes(), "application/pdf",
                        filename, download=req.qbool("download", False))


def case_decision(req: Request, case_id: str) -> Response:
    store = get_store()
    case = store.get(case_id)
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    payload = req.json()
    decision = str(payload.get("decision") or "").strip().lower()
    analyst = str(payload.get("analyst")
                  or req.header("x-analyst") or "").strip()
    if decision not in DECISIONS:
        return Response.error(
            400, "decision must be one of %s" %
            (list(DECISIONS),), got=decision)
    if not analyst:
        return Response.error(
            400, "an analyst identity is required; an unattributed "
            "decision is not auditable")
    try:
        case = record_decision(
            case, decision, analyst, note=str(
                payload.get("note") or ""), override_verdict=str(
                payload.get("override_verdict") or ""))
    except ValueError as exc:
        return Response.error(400, str(exc))
    receipt = None
    try:
        receipt = get_chain().record_action(case.case_number, decision, analyst)
        case.chain_receipts.append(receipt)
    except Exception as exc:  # noqa: BLE001 - anchoring must not lose the decision
        # The decision is the audited fact; the receipt is corroboration. If the
        # RPC is down the decision still stands and the failure is recorded on the
        # case rather than swallowed.
        log.warning(
            "decision anchoring failed for %s: %s",
            case.case_number,
            exc)
        case.errors.append("decision anchoring failed: %s" % str(exc)[:120])
    store.save(case)
    store.log_event(case.id, "decision_" + decision, analyst,
                    str(payload.get("note") or "")[:400])
    summary = case.summary()
    get_bus().publish("decision", {"case_number": case.case_number,
                                   "decision": decision, "analyst": analyst})
    return Response.ok({"case": summary,
                        "receipt": receipt.to_dict() if receipt is not None else None,
                        "next_actions": case_bundle(case.id)["next_actions"]})


def case_reinvestigate(req: Request, case_id: str) -> Response:
    case = reinvestigate(case_id, anchor=req.qbool("anchor", True))
    if case is None:
        return Response.error(404, "no such case", case_id=case_id)
    summary = case.summary()
    get_bus().publish("case", summary)
    return Response.ok({"case": summary})


def campaigns(req: Request) -> Response:
    return Response.ok(
        {"campaigns": get_store().campaigns(limit=req.qint("limit", 50))})


def search(req: Request) -> Response:
    query = req.q("q").strip()
    if not query:
        return Response.error(400, "q is required")
    return Response.ok(
        get_store().search(
            query,
            limit=min(
                req.qint(
                    "limit",
                    50),
                200)))


def by_ioc(req: Request, value: str) -> Response:
    cases = get_store().by_ioc(value, limit=min(req.qint("limit", 50), 200))
    return Response.ok(
        {"indicator": value, "count": len(cases), "cases": cases})


def privacy_policy(req: Request) -> Response:
    return Response.ok({"policy": policy_summary(),
                       "status": retention_status()})


def privacy_retention(req: Request) -> Response:
    """Run the retention sweep. Defaults to a dry run, and says which it did.

    ``dry_run`` defaults to true because the destructive reading of an ambiguous
    request is the wrong one to guess at. The response always reports the mode it
    ran in, so a caller cannot mistake a preview for a purge.
    """
    dry_run = req.qbool("dry_run", True)
    if req.method == "POST":
        payload = req.json()
        if "dry_run" in payload:
            dry_run = bool(payload["dry_run"])
    files = apply_retention(dry_run=dry_run)
    cases = get_store().redact_expired(dry_run=dry_run)
    get_bus().publish("retention", {"dry_run": dry_run,
                                    "cases": cases.get("cases_affected", 0)})
    return Response.ok({"dry_run": dry_run, "files": files, "cases": cases,
                        "policy": policy_summary()})


def clear_cases(req: Request) -> Response:
    """Purge all cases, campaigns, signals, and evidence from the database."""
    store = get_store()
    count = store.clear_all()
    try:
        reports_dir = EVIDENCE_DIR / "reports"
        if reports_dir.exists():
            for f in reports_dir.glob("*.pdf"):
                try:
                    f.unlink(missing_ok=True)
                except Exception:
                    pass
    except Exception:
        pass
    get_bus().publish("cases_purged", {"count": count})
    return Response.ok({"purged": count, "message": "all imported cases cleared successfully"}, status=200)


def chain_verify(req: Request, case_ref: str) -> Response:
    chain = get_chain()
    case = get_store().get(case_ref)
    reference = case.case_number if case is not None else case_ref
    local = chain.verify_local(reference)
    out: Dict[str, Any] = {"case_number": reference, "local": local,
                           "mode": "live" if get_settings().has_chain() else "simulated"}
    if req.qbool("onchain", False) and get_settings().has_chain():
        try:
            out["onchain"] = chain.verify_onchain(reference)
        except Exception as exc:  # noqa: BLE001 - an RPC failure is a result, not a crash
            out["onchain_error"] = str(exc)[:200]
    return Response.ok(out)


def events_since(req: Request) -> Response:
    return Response.ok(get_bus().since(req.qint("since", 0),
                                       limit=min(req.qint("limit", 200), 400)))


def openapi(req: Request) -> Response:
    """A hand-written route index.

    Not a generated OpenAPI document: generating one would mean either depending
    on FastAPI (which may be absent) or maintaining a second schema by hand. This
    lists what exists, which is what a client actually needs from this endpoint.
    """
    return Response.ok({"service": "mailtrace", "routes": [
        {"method": m, "path": p, "summary": (h.__doc__ or "").strip().split("\n")[0]}
        for m, p, h in ROUTE_INDEX]})


# --------------------------------------------------------------------------
# Routing table
# --------------------------------------------------------------------------

def alert_test(req: Request) -> Response:
    payload = req.json() if req.body else {}
    webhook_url = payload.get("webhook_url") or None
    res = send_test_alert(webhook_url=webhook_url)
    return Response.ok(res, status=200 if res.get("ok") else 400)


Handler = Callable[..., Response]
ROUTE_INDEX: List[Tuple[str, str, Handler]] = [
    ("GET", "/api/health", health),
    ("GET", "/api/routes", openapi),
    ("GET", "/api/config", get_config),
    ("PATCH", "/api/config", patch_config),
    ("POST", "/api/config", patch_config),
    ("POST", "/api/alerts/test", alert_test),
    ("GET", "/api/stats", stats),
    ("GET", "/api/model", model_card),
    ("POST", "/api/ingest", ingest),
    ("POST", "/api/ingest/demo", ingest_demo),
    ("POST", "/api/ingest/directory", ingest_path),
    ("GET", "/api/cases", list_cases),
    ("POST", "/api/cases/clear", clear_cases),
    ("DELETE", "/api/cases", clear_cases),
    ("GET", "/api/cases/{case_id}", get_case),
    ("GET", "/api/cases/{case_id}/audit", case_audit),
    ("GET", "/api/cases/{case_id}/graph", case_graph),
    ("GET", "/api/cases/{case_id}/map", case_map),
    ("GET", "/api/cases/{case_id}/export", case_export),
    ("GET", "/api/cases/{case_id}/takedown", case_takedown),
    ("GET", "/api/cases/{case_id}/report", case_report),
    ("POST", "/api/cases/{case_id}/report", case_report),
    ("POST", "/api/cases/{case_id}/decision", case_decision),
    ("POST", "/api/cases/{case_id}/reinvestigate", case_reinvestigate),
    ("GET", "/api/campaigns", campaigns),
    ("GET", "/api/search", search),
    ("GET", "/api/ioc/{value}", by_ioc),
    ("GET", "/api/privacy", privacy_policy),
    ("GET", "/api/privacy/retention", privacy_retention),
    ("POST", "/api/privacy/retention", privacy_retention),
    ("GET", "/api/chain/{case_ref}", chain_verify),
    ("GET", "/api/events/since", events_since),
]



def _compile(path: str) -> Pattern[str]:
    """Turn ``/api/cases/{case_id}/map`` into an anchored regex.

    Path parameters match anything but ``/`` so that a case number, a case id and
    a URL-encoded indicator all work in the same slot. ``/api/ioc/{value}`` is
    the reason segments are not restricted to a word charset.
    """
    pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", path)
    return re.compile("^" + pattern + "/?$")


ROUTES: List[Tuple[str, Pattern[str], Handler]] = [
    (method, _compile(path), handler) for method, path, handler in ROUTE_INDEX
]


def dispatch(req: Request) -> Response:
    """Resolve and run one request. Never raises."""
    allowed: List[str] = []
    for method, pattern, handler in ROUTES:
        match = pattern.match(req.path)
        if match is None:
            continue
        if method != req.method:
            allowed.append(method)
            continue
        try:
            return handler(req, **match.groupdict())
        except Exception as exc:  # noqa: BLE001 - one bad request must not stop the API
            ref = "err-%d" % int(time.time() * 1000)
            log.exception(
                "unhandled error serving %s %s [%s]",
                req.method,
                req.path,
                ref)
            return Response.error(
                500,
                "internal error: %s" %
                type(exc).__name__,
                reference=ref,
                detail=str(exc)[
                    :300])
    if allowed:
        return Response(status=405,
                        body=json.dumps({"error": "method not allowed",
                                         "allowed": sorted(set(allowed))}).encode(),
                        headers={"Allow": ", ".join(sorted(set(allowed)))})
    return Response.error(404, "no such route", path=req.path)
