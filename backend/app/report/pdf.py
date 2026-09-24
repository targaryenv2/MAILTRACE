"""The forensic report: the artefact an analyst hands to someone else.

Two renderers, one document. The content is built once as a list of layout
blocks and painted by whichever engine is available - ReportLab when installed,
:mod:`app.report.minipdf` otherwise - so the report never silently degrades into
"PDF generation unavailable" on a machine where pip is blocked. The engine used
is printed in the footer, because a reader is entitled to know how the file in
their hand was produced.

Design rules this file follows, in priority order:

1. **Every claim carries its provenance.** A location from a MaxMind database
   and a location from the demo fixture look different on the page. So does a
   blockchain receipt from a real transaction versus a simulated one. A report
   that hides that distinction is worse than no report.
2. **Verdict and confidence stay separate.** How bad, and how sure, are two
   numbers. They are printed side by side and never combined.
3. **Gaps are stated, not skipped.** Unlocated hops, unavailable intel, refused
   attribution and parse failures each get a line saying so.
4. **PII masking is honoured.** When ``PII_MASKING`` is on, addresses in the
   report are masked with the same one-way tag used everywhere else, and the
   cover page says the document is masked. Turning it off is an explicit act
   recorded on the page.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config import EVIDENCE_DIR, get_settings
from ..privacy import mask_email, mask_text
from ..schemas import (
    RISK_CLEAN, RISK_CRITICAL, RISK_HIGH, RISK_LOW, RISK_MEDIUM,
    SOURCE_FIXTURE, SOURCE_LIVE, SOURCE_SIMULATED, SOURCE_UNAVAILABLE, Case,
)
from . import mapfig
from .minipdf import A4, MiniPdf, string_width

log = logging.getLogger(__name__)

# --- palette. Print-first: white paper, dark ink, colour used only for meaning.
INK = (0.09, 0.11, 0.16)
MUTED = (0.42, 0.46, 0.53)
RULE = (0.84, 0.86, 0.89)
ZEBRA = (0.965, 0.972, 0.980)
ACCENT = (0.10, 0.33, 0.68)
PANEL = (0.957, 0.969, 0.988)
WHITE = (1.0, 1.0, 1.0)

SEVERITY_COLOUR: Dict[str, Tuple[float, float, float]] = {
    RISK_CRITICAL: (0.70, 0.11, 0.15),
    RISK_HIGH: (0.83, 0.35, 0.05),
    RISK_MEDIUM: (0.68, 0.50, 0.03),
    RISK_LOW: (0.20, 0.42, 0.30),
    RISK_CLEAN: (0.13, 0.45, 0.28),
}
SOURCE_LABEL: Dict[str, str] = {
    SOURCE_LIVE: "live",
    SOURCE_FIXTURE: "fixture",
    SOURCE_SIMULATED: "simulated",
    SOURCE_UNAVAILABLE: "unavailable",
    "offline-table": "offline table",
    "computed": "computed",
}

MARGIN = 42.0
PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 2 * MARGIN


# ---------------------------------------------------------------------------
# canvas adapters. The paint engine below works top-down in points; both PDF
# engines are bottom-up, so the flip happens here and nowhere else.
# ---------------------------------------------------------------------------
class _MiniCanvas:
    engine = "minipdf"

    def __init__(self) -> None:
        self.pdf = MiniPdf(PAGE_W, PAGE_H)

    def text(self, x, y, s, size=9.0, bold=False, colour=INK):
        self.pdf.text(x, PAGE_H - y, s, size, bold, colour)

    def line(self, x1, y1, x2, y2, width=0.6, colour=RULE, dash=None):
        self.pdf.line(x1, PAGE_H - y1, x2, PAGE_H - y2, width, colour, dash)

    def rect(self, x, y, w, h, fill=None, stroke=None, width=0.6):
        self.pdf.rect(x, PAGE_H - y - h, w, h, fill, stroke, width)

    def circle(self, cx, cy, r, fill=None, stroke=None, width=0.6):
        self.pdf.circle(cx, PAGE_H - cy, r, fill, stroke, width)

    def width_of(self, s, size=9.0, bold=False):
        return string_width(s, size, bold)

    def new_page(self):
        self.pdf.new_page()

    def save(self, path):
        return self.pdf.save(path)


class _ReportlabCanvas:
    engine = "reportlab"

    def __init__(self) -> None:
        from reportlab.pdfgen import canvas as rl_canvas  # noqa: PLC0415

        self._buf = None
        self._path = None
        self._maker = rl_canvas.Canvas
        self.c = None

    def open(self, path: str) -> None:
        self._path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.c = self._maker(path, pagesize=A4)
        self.c.setTitle("MailTrace forensic report")

    def text(self, x, y, s, size=9.0, bold=False, colour=INK):
        self.c.setFillColorRGB(*colour)
        self.c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        self.c.drawString(x, PAGE_H - y, s)

    def line(self, x1, y1, x2, y2, width=0.6, colour=RULE, dash=None):
        self.c.saveState()
        self.c.setStrokeColorRGB(*colour)
        self.c.setLineWidth(width)
        if dash:
            self.c.setDash(dash[0], dash[1])
        self.c.line(x1, PAGE_H - y1, x2, PAGE_H - y2)
        self.c.restoreState()

    def rect(self, x, y, w, h, fill=None, stroke=None, width=0.6):
        self.c.saveState()
        if fill is not None:
            self.c.setFillColorRGB(*fill)
        if stroke is not None:
            self.c.setStrokeColorRGB(*stroke)
            self.c.setLineWidth(width)
        self.c.rect(x, PAGE_H - y - h, w, h,
                    stroke=1 if stroke is not None else 0,
                    fill=1 if fill is not None else 0)
        self.c.restoreState()

    def circle(self, cx, cy, r, fill=None, stroke=None, width=0.6):
        self.c.saveState()
        if fill is not None:
            self.c.setFillColorRGB(*fill)
        if stroke is not None:
            self.c.setStrokeColorRGB(*stroke)
            self.c.setLineWidth(width)
        self.c.circle(cx, PAGE_H - cy, r,
                      stroke=1 if stroke is not None else 0,
                      fill=1 if fill is not None else 0)
        self.c.restoreState()

    def width_of(self, s, size=9.0, bold=False):
        return self.c.stringWidth(
            s, "Helvetica-Bold" if bold else "Helvetica", size)

    def new_page(self):
        self.c.showPage()

    def save(self, path):
        self.c.save()
        return self._path or path


class _NullCanvas:
    """Measures pagination without drawing. Used for the "page n of N" count."""

    engine = "null"

    def __init__(self) -> None:
        self.pages = 1

    def text(self, *a, **k):
        return None

    line = rect = circle = text

    def width_of(self, s, size=9.0, bold=False):
        return string_width(s, size, bold)

    def new_page(self):
        self.pages += 1

    def save(self, path):
        return path


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------
def _wrap(canvas: Any, text: str, width: float, size: float, bold: bool = False
          ) -> List[str]:
    """Greedy word wrap. Over-long single words are hard-split so a 200-character
    URL cannot run off the page and out of the evidence."""
    if not text:
        return [""]
    lines: List[str] = []
    for para in str(text).split("\n"):
        words, cur = para.split(), ""
        for word in words:
            trial = (cur + " " + word).strip()
            if canvas.width_of(trial, size, bold) <= width or not cur:
                if canvas.width_of(trial, size, bold) > width and not cur:
                    piece = ""
                    for ch in word:
                        if canvas.width_of(
                                piece + ch, size, bold) > width and piece:
                            lines.append(piece)
                            piece = ch
                        else:
                            piece += ch
                    cur = piece
                else:
                    cur = trial
            else:
                lines.append(cur)
                cur = word
        lines.append(cur)
    return lines or [""]


def _fmt_dt(value: str) -> str:
    if not value:
        return "not recorded"
    return str(value).replace("T", " ").replace("+00:00", " UTC")


def _yn(value: Any) -> str:
    return "yes" if value else "no"


def _mask(value: str, on: bool) -> str:
    return mask_email(value) if (
        on and value and "@" in value) else (value or "")


def _short(text: str, limit: int) -> str:
    """Trim for a fixed-width chip. The full text is always printed nearby."""
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---------------------------------------------------------------------------
# content
# ---------------------------------------------------------------------------
def _blocks(case: Case, masking: bool) -> List[Dict[str, Any]]:
    """Build the whole document as engine-independent blocks."""
    st = get_settings()
    pe = case.parsed_email
    auth = pe.auth
    v = case.verdict
    b: List[Dict[str, Any]] = []

    def h(text: str) -> None:
        b.append({"t": "h", "text": text})

    def p(text: str, size: float = 8.6, colour=INK) -> None:
        b.append({"t": "p", "text": text, "size": size, "colour": colour})

    # --- 1. cover / executive summary -------------------------------------
    b.append({"t": "cover", "case": case, "masking": masking})
    h("1. Executive summary")
    b.append({"t": "chips", "items": [
        ("verdict", v.label, SEVERITY_COLOUR.get(v.risk_level, ACCENT)),
        ("threat class", v.threat_class, ACCENT),
        ("risk score", "%.1f / 100" % v.risk_score, SEVERITY_COLOUR.get(v.risk_level, ACCENT)),
        ("confidence", "%.1f%% (%s)" % (v.confidence, v.confidence_band), MUTED),
        ("recommended action", _short(v.recommended_action.replace("_", " "), 46), ACCENT),
    ]})
    if len(v.recommended_action) > 46:
        p("Recommended action in full: %s" % v.recommended_action, 8.4)
    p("Risk score answers how dangerous this message is. Confidence answers how "
      "well the evidence supports that answer. They are independent: a low-evidence "
      "case can be scored high risk and still require review.", 8.0, MUTED)
    if v.narrative:
        p(mask_text(v.narrative) if masking else v.narrative)
        p("Narrative source: %s." % v.narrative_source, 7.8, MUTED)
    if v.threat_class_reason:
        p("Classification basis: %s" % v.threat_class_reason, 8.2)
    if v.requires_human_review:
        b.append({"t": "banner",
                  "text": "Human review required before any enforcement action.",
                  "colour": SEVERITY_COLOUR[RISK_MEDIUM]})
    if v.ambiguity_flags:
        b.append({"t": "bullets", "items": list(v.ambiguity_flags),
                  "label": "Reasons this case is not self-evident"})
    if case.errors:
        b.append({"t": "bullets", "items": list(case.errors),
                  "label": "Processing errors recorded during analysis"})

    # --- 2. evidence integrity -------------------------------------------
    h("2. Evidence integrity and chain of custody")
    b.append({"t": "kv", "rows": [
        ("Case identifier", case.case_number),
        ("Internal case id", case.id),
        ("Source", "%s%s" % (case.source, " (%s)" % case.filename if case.filename else "")),
        ("Reported by", _mask(case.reported_by, masking) or "not recorded"),
        ("Raw message SHA-256", case.email_hash or "not computed"),
        ("Campaign fingerprint", case.fingerprint or "not computed"),
        ("Opened", _fmt_dt(case.created_at)),
        ("Completed", _fmt_dt(case.completed_at)),
    ]})
    receipts = case.chain_receipts
    if receipts:
        anchored = [r for r in receipts if not r.simulated]
        p("%d custody entries were written for this case: %d anchored on chain, "
          "%d recorded locally in simulation mode. A simulated entry proves the "
          "payload hash was computed at the time shown; it does not prove "
          "publication, and is labelled that way in the table below." %
          (len(receipts), len(anchored), len(receipts) - len(anchored)), 8.2)
        b.append({"t": "table",
                  "cols": [("action", 0.16, "l"), ("payload hash", 0.24, "l"),
                           ("transaction", 0.30, "l"), ("block", 0.09, "l"),
                           ("written", 0.21, "l")],
                  "rows": [[r.action,
                            (r.payload_hash or "")[:24],
                            (r.tx_hash or "-") + ("  [simulated]" if r.simulated else ""),
                            str(r.block_number) if r.block_number else "-",
                            _fmt_dt(r.written_at)] for r in receipts[-14:]]})
    else:
        p("No custody entries were written for this case.", 8.4,
          SEVERITY_COLOUR[RISK_MEDIUM])

    # --- 3. message identity ---------------------------------------------
    b.append({"t": "pagebreak"})
    h("3. Message identity")
    b.append({"t": "kv", "rows": [
        ("Display name", pe.from_name or "(none)"),
        ("From address", _mask(pe.from_address, masking)),
        ("From domain", pe.from_domain or "(none)"),
        ("Reply-To", _mask(pe.reply_to, masking) or "(absent)"),
        ("Return-Path", _mask(pe.return_path, masking) or "(absent)"),
        ("Message-ID", pe.message_id or "(absent)"),
        ("Date header", pe.date or "(absent)"),
        ("Subject", pe.subject or "(empty)"),
        ("To", ", ".join(_mask(a, masking) for a in pe.to) or "(none)"),
        ("Cc", ", ".join(_mask(a, masking) for a in pe.cc) or "(none)"),
        ("Size", "%d bytes" % pe.size_bytes),
        ("Parse status", "complete" if pe.parse_complete
         else "incomplete: " + "; ".join(pe.parse_errors)),
    ]})

    h("4. Authentication and protocol analysis")
    b.append({"t": "table",
              "cols": [("mechanism", 0.16, "l"), ("result", 0.14, "l"),
                       ("signing / envelope domain", 0.32, "l"),
                       ("aligned with From", 0.18, "l"), ("meaning", 0.20, "l")],
              "rows": [
                  ["SPF", auth.spf or "none", auth.spf_domain or "-",
                   _yn(auth.spf_aligned),
                   "envelope sender authorised" if auth.spf == "pass"
                   else "envelope sender not authorised"],
                  ["DKIM", auth.dkim or "none", auth.dkim_domain or "-",
                   _yn(auth.dkim_aligned),
                   "signature verified" if auth.dkim == "pass"
                   else "no verified signature"],
                  ["DMARC", auth.dmarc or "none",
                   "policy=%s" % (auth.dmarc_policy or "unset"), "-",
                   "identifier alignment enforced" if auth.dmarc == "pass"
                   else "alignment not established"],
              ]})
    p("Alignment, not the individual pass, is what makes a From header "
      "trustworthy: SPF can pass for an attacker's own domain while the visible "
      "From address is forged. Envelope-from domain observed: %s. Source: %s."
      % (auth.envelope_from_domain or "not present", SOURCE_LABEL.get(auth.source, auth.source)),
      8.0, MUTED)
    if auth.parse_notes:
        b.append({"t": "bullets", "items": list(auth.parse_notes),
                  "label": "Notes from parsing the authentication headers"})
    if pe.received_chain:
        b.append({"t": "table",
                  "cols": [("hop", 0.06, "l"), ("from host", 0.26, "l"),
                           ("from ip", 0.15, "l"), ("received by", 0.26, "l"),
                           ("timestamp", 0.27, "l")],
                  "rows": [[str(r.index), r.from_host or "-", r.from_ip or "-",
                            r.by_host or "-", r.timestamp or "-"]
                           for r in pe.received_chain]})
        p("Received headers are prepended by each MTA, so the bottom-most header "
          "is the earliest hop. They are printed here earliest-first, the order an "
          "analyst reads a trace in.", 7.8, MUTED)

    # --- 5. origin and relay path ----------------------------------------
    b.append({"t": "pagebreak"})
    h("5. Origin traceability")
    origin = case.origin or {}
    if origin.get("determined"):
        b.append({"t": "kv", "rows": [
            ("Earliest reliable node", "hop %s - %s" % (origin.get("hop_index"),
                                                        origin.get("ip", ""))),
            ("Reverse DNS", origin.get("hostname") or "none presented"),
            ("Location", origin.get("place") or "unresolved"),
            ("Precision", str(origin.get("precision", "unknown"))),
            ("Network", ("%s %s" % (origin.get("asn", ""), origin.get("isp", ""))).strip()
             or "unknown"),
            ("Geolocation source", SOURCE_LABEL.get(str(origin.get("geo_source", "")),
                                                    str(origin.get("geo_source", "")))),
            ("Confidence in origin claim", str(origin.get("confidence", "none"))),
            ("Hops after the origin", str(origin.get("later_hops", 0))),
        ]})
        if origin.get("indicators"):
            b.append({"t": "bullets", "items": list(origin["indicators"]),
                      "label": "Infrastructure indicators at the origin node"})
    else:
        p("No routable sending node could be established from the Received chain. "
          "Reason: %s. This is a finding, not a failure: a chain that cannot "
          "support an origin claim is itself evidence of header manipulation." %
          origin.get("reason", "not recorded"), 8.6, SEVERITY_COLOUR[RISK_MEDIUM])

    lay = mapfig.layout(case.relay_hops, origin.get(
        "hop_index") if origin.get("determined") else None)
    if lay["drawable"]:
        b.append({"t": "map", "layout": lay})
    if lay["unlocated"]:
        b.append({"t": "bullets",
                  "items": ["hop %s (%s): %s" % (u["index"],
                                                 u["ip"] or "no address",
                                                 u["reason"]) for u in lay["unlocated"]],
                  "label": "Hops deliberately not plotted"})
    if case.relay_hops:
        b.append({"t": "table",
                  "cols": [("hop", 0.05, "l"), ("address", 0.14, "l"),
                           ("reverse dns", 0.21, "l"), ("location", 0.18, "l"),
                           ("network", 0.22, "l"), ("delay", 0.08, "r"),
                           ("flag", 0.12, "l")],
                  "rows": [[str(hop.index), hop.ip or "-", hop.hostname or "-",
                            ", ".join(x for x in (hop.location.city, hop.location.country)
                                      if x) or "unresolved",
                            ("%s %s" % (hop.location.asn, hop.location.isp)).strip() or "-",
                            ("%.0fs" % hop.delay_seconds) if hop.delay_seconds else "-",
                            "anomaly" if hop.is_anomalous else "ok"]
                           for hop in case.relay_hops]})
        anomalies = [(hop.index, r) for hop in case.relay_hops
                     for r in hop.anomaly_reasons]
        if anomalies:
            b.append({"t": "bullets", "items": ["hop %d: %s" % (
                i, r) for i, r in anomalies[:16]], "label": "Relay anomalies"})

    # --- 6. detection evidence -------------------------------------------
    b.append({"t": "pagebreak"})
    h("6. Detection evidence")
    triggered = [s for s in case.signals if s.triggered]
    p("%d checks ran; %d produced evidence. Weight is a log-odds contribution: "
      "positive values push toward malicious, negative toward benign, and they sum "
      "before the logistic transform that produces the risk score." %
      (len(case.signals), len(triggered)), 8.2)
    if triggered:
        b.append({"t": "table",
                  "cols": [("check", 0.19, "l"), ("finding", 0.34, "l"),
                           ("severity", 0.10, "l"), ("weight", 0.08, "r"),
                           ("category", 0.12, "l"), ("ATT&CK", 0.17, "l")],
                  "rows": [[s.title, s.result or s.detail or "-", s.severity,
                            "%+.2f" % s.weight, s.category,
                            (s.mitre_technique or "-")] for s in triggered],
                  "severity_col": 2})
    sb = v.score_breakdown or {}
    if sb:
        rows = [[k.replace("_", " "), "%+.3f" % float(val)]
                for k, val in sb.items() if k != "total_logit"]
        rows.append(["total log-odds", "%+.3f" %
                    float(sb.get("total_logit", 0.0))])
        b.append({"t": "table", "cols": [("evidence group", 0.60, "l"),
                                         ("log-odds", 0.40, "r")], "rows": rows})
        p("risk = 100 / (1 + e^-total). The prior term is the base rate the model "
          "starts from before seeing any evidence, so a message with no findings "
          "scores near zero rather than at fifty.", 7.8, MUTED)

    ml = case.ml
    h("7. Machine-learning assessment")
    if ml.available:
        b.append({"t": "kv", "rows": [
            ("Model", "%s %s" % (ml.model_name, ml.model_version)),
            ("Phishing probability", "%.3f" % ml.probability),
            ("Model label", ml.label),
            ("Decision threshold", "%.2f" % ml.threshold),
            ("Baseline (no evidence)", "%.3f" % ml.base_value),
            ("Source", SOURCE_LABEL.get(ml.source, ml.source)),
        ]})
        if ml.top_features:
            b.append({"t": "table",
                      "cols": [("feature", 0.42, "l"), ("value", 0.14, "r"),
                               ("Shapley contribution", 0.22, "r"), ("pushes", 0.22, "l")],
                      "rows": [[f.feature, "%.3f" % f.value, "%+.4f" % f.contribution,
                                f.direction] for f in ml.top_features[:12]]})
            p("Contributions are exact Shapley values for this linear model, not "
              "approximations: they sum with the baseline to the model's own output, "
              "which is asserted at prediction time.", 7.8, MUTED)
        if ml.notes:
            p(ml.notes, 8.0, MUTED)
    else:
        p("No trained model was available for this case; the verdict rests on the "
          "rule and protocol evidence above. %s" % (ml.notes or ""), 8.4, MUTED)

    # --- 8. intel, sandbox, technique ------------------------------------
    b.append({"t": "pagebreak"})
    h("8. Threat intelligence")
    if case.intel:
        b.append({"t": "table",
                  "cols": [("provider", 0.16, "l"), ("subject", 0.24, "l"),
                           ("status", 0.12, "l"), ("summary", 0.34, "l"),
                           ("source", 0.14, "l")],
                  "rows": [[r.provider, r.subject, r.status, r.summary or r.error or "-",
                            "%s%s" % (SOURCE_LABEL.get(r.source, r.source),
                                      " (cached)" if r.cached else "")]
                           for r in case.intel]})
    else:
        p("No threat-intelligence lookups were performed for this case.", 8.4, MUTED)

    h("9. Link and attachment analysis")
    if pe.urls:
        b.append({"t": "table",
                  "cols": [("url", 0.44, "l"), ("registrable domain", 0.20, "l"),
                           ("where", 0.12, "l"), ("observations", 0.24, "l")],
                  "rows": [[u.url[:120], u.registrable_domain or "-", u.location,
                            "; ".join(u.reasons) or "none"] for u in pe.urls[:14]]})
    else:
        p("No links were present in the message body.", 8.4, MUTED)
    if pe.attachments:
        b.append({"t": "table",
                  "cols": [("filename", 0.26, "l"), ("declared type", 0.18, "l"),
                           ("detected", 0.14, "l"), ("size", 0.10, "r"),
                           ("sha-256", 0.20, "l"), ("flags", 0.12, "l")],
                  "rows": [[a.filename, a.mime_type, a.detected_type or "-",
                            "%d" % a.size_bytes, a.sha256[:16],
                            ", ".join(x for x, on in (
                                ("macro", a.is_macro_capable), ("exe", a.is_executable),
                                ("archive", a.is_archive),
                                ("ext mismatch", a.extension_mismatch),
                                ("double ext", a.double_extension)) if on) or "-"]
                           for a in pe.attachments]})
    if pe.has_qr_code:
        p("A QR code was detected in this message. Payloads: %s"
          % "; ".join(pe.qr_payloads or ["not decoded"]), 8.4)
    if case.sandbox:
        b.append({"t": "table",
                  "cols": [("url examined", 0.30, "l"), ("status", 0.12, "l"),
                           ("verdict", 0.12, "l"), ("landing page", 0.26, "l"),
                           ("source", 0.20, "l")],
                  "rows": [[s.url[:80], s.status, s.verdict,
                            (s.page_title or s.final_url or "-")[:60],
                            SOURCE_LABEL.get(s.source, s.source)] for s in case.sandbox]})
        notes = [n for s in case.sandbox for n in (s.indicators or [])]
        if notes:
            b.append({"t": "bullets", "items": notes[:12],
                      "label": "Observations from link examination"})

    h("10. ATT&CK technique mapping")
    if case.mitre:
        b.append({"t": "table",
                  "cols": [("technique", 0.14, "l"), ("name", 0.32, "l"),
                           ("tactic", 0.20, "l"), ("evidence", 0.34, "l")],
                  "rows": [[str(m.get("technique_id", "")), str(m.get("name", "")),
                            str(m.get("tactic", "")),
                            "; ".join(m.get("evidence", []) or [])[:120]]
                           for m in case.mitre]})
    else:
        p("No ATT&CK techniques were mapped for this case.", 8.4, MUTED)

    # --- 11. attribution and campaign ------------------------------------
    b.append({"t": "pagebreak"})
    h("11. Attribution")
    att = case.attribution
    b.append({"t": "kv", "rows": [
        ("Assessed actor type", att.actor_type),
        ("Confidence", "%.1f%% (%s)" % (att.confidence, att.confidence_band or "n/a")),
        ("Origin", att.origin_place or "not established"),
        ("Origin precision", att.origin_precision or "n/a"),
        ("Infrastructure", ", ".join(att.infrastructure) or "not characterised"),
        ("Correlation cluster", "%s (%d cases)" % (att.cluster_id or "none",
                                                   att.cluster_size)),
        ("Basis", SOURCE_LABEL.get(att.source, att.source)),
    ]})
    p("Attribution here describes a mechanism - a spoofed domain, a hijacked "
      "mailbox, anonymised infrastructure, a directly operated account - and never "
      "a person. Confidence is capped below certainty because header evidence "
      "alone cannot exclude a well-resourced impersonator.", 8.0, MUTED)
    if att.reasons:
        b.append({"t": "bullets",
                  "items": list(att.reasons),
                  "label": "Supporting reasons"})
    if att.alternatives:
        b.append({"t": "bullets",
                  "items": ["%s - %s" % (a.get("actor_type", "?"),
                                         a.get("why", a.get("reason", "")))
                            if isinstance(a, dict) else str(a) for a in att.alternatives],
                  "label": "Alternative explanations not excluded"})
    if att.shared_indicators:
        b.append({"t": "bullets", "items": list(att.shared_indicators)[:12],
                  "label": "Indicators shared with correlated cases"})
    if att.notes:
        p(att.notes, 8.0, MUTED)

    h("12. Campaign and exposure")
    camp = case.campaign
    br = case.blast_radius
    b.append({"t": "kv", "rows": [
        ("Campaign", camp.id or "not grouped"),
        ("Messages in campaign", str(camp.case_count)),
        ("This message is a duplicate", _yn(camp.is_duplicate)),
        ("Recipients identified", str(br.total_recipients)),
        ("Opened / clicked", "%d / %d" % (br.total_opened, br.total_clicked)),
        ("Credentials submitted", str(br.total_credentials_submitted)),
        ("Reported by recipients", str(br.total_reported)),
        ("High-value targets", str(br.high_value_targets)),
        ("Departments affected", ", ".join(br.departments_affected) or "none identified"),
        ("Exposure data source", SOURCE_LABEL.get(br.source, br.source)),
    ]})
    if br.matched_by:
        p("Exposure matched by: %s." % "; ".join(br.matched_by), 8.0, MUTED)
    if br.notes:
        p(br.notes, 8.0, MUTED)
    if br.exposures:
        b.append({"t": "table",
                  "cols": [("recipient", 0.30, "l"), ("role", 0.24, "l"),
                           ("dept", 0.16, "l"), ("opened", 0.09, "l"),
                           ("clicked", 0.09, "l"), ("submitted", 0.12, "l")],
                  "rows": [[_mask(e.recipient_email, masking), e.role or "-",
                            e.department or "-", _yn(e.opened), _yn(e.clicked),
                            _yn(e.submitted_credentials)] for e in br.exposures[:18]]})

    h("13. Indicators of compromise")
    if case.iocs:
        b.append({"t": "table",
                  "cols": [("type", 0.16, "l"), ("value", 0.44, "l"),
                           ("context", 0.28, "l"), ("confidence", 0.12, "r")],
                  "rows": [[i.ioc_type, i.value[:90], i.context or "-",
                            "%d%%" % i.confidence] for i in case.iocs[:24]]})
        p("These indicators are safe to share. They are drawn from the message "
          "itself, carry a per-indicator confidence, and are exportable as STIX "
          "2.1 bundles for a partner platform.", 7.8, MUTED)
    else:
        p("No indicators were extracted from this message.", 8.4, MUTED)

    # --- 14. investigation trail -----------------------------------------
    b.append({"t": "pagebreak"})
    h("14. Investigation trail")
    p("Each step below records what the investigator chose to check, why it chose "
      "it at that point, and what came back. The sequence is not fixed: later "
      "checks are selected from the findings of earlier ones.", 8.2)
    if case.trail:
        b.append({"t": "table",
                  "cols": [("#", 0.05, "l"), ("action", 0.17, "l"),
                           ("why this step", 0.30, "l"), ("result", 0.28, "l"),
                           ("status", 0.09, "l"), ("ms", 0.11, "r")],
                  "rows": [[str(s.index), s.action, s.reasoning or "-",
                            s.result or "-", s.status,
                            "%d" % s.duration_ms] for s in case.trail]})
    h("15. Workflow and disposition")
    action = case.action
    sla = case.sla
    b.append({"t": "kv", "rows": [
        ("Case status", case.status),
        ("Recommended action", action.recommended_action.replace("_", " ")),
        ("Decision status", action.status),
        ("Analyst", _mask(action.analyst, masking) or "unassigned"),
        ("Analyst note", action.analyst_note or "none"),
        ("Verdict overridden to", action.override_verdict or "not overridden"),
        ("Decision recorded at", _fmt_dt(action.decided_at)),
        ("Decision anchored", action.tx_hash or "not anchored"),
        ("SLA target", "%d minutes" % sla.target_minutes),
        ("SLA deadline", _fmt_dt(sla.deadline_at)),
        ("SLA breached", _yn(sla.breached)),
    ]})
    if case.takedown and case.takedown.target_domain:
        td = case.takedown
        b.append({"t": "kv", "rows": [
            ("Takedown target", td.target_domain),
            ("Registrar", td.registrar or "not established"),
            ("Abuse contact", td.abuse_contact or "not established"),
            ("Notice prepared", _fmt_dt(td.generated_at)),
            ("Notice sent", _yn(td.sent)),
        ]})
        p("A takedown notice was drafted but is never sent automatically. Sending "
          "is an analyst decision with legal consequences.", 8.0, MUTED)

    h("16. Handling, provenance and limitations")
    caps = case.capabilities or st.capability_report()
    b.append({"t": "table",
              "cols": [("subsystem", 0.34, "l"), ("mode for this case", 0.66, "l")],
              "rows": [[k.replace("_", " "), str(val)] for k, val in sorted(caps.items())]})
    b.append({"t": "bullets", "label": "Limitations a reader must weigh", "items": [
        "Values marked fixture come from bundled demonstration data, not a live "
        "provider, and must not be relied on outside a demonstration.",
        "Values marked simulated for the custody trail prove a hash was computed "
        "locally; only a transaction hash on a public chain proves publication.",
        "Geolocation resolves an address to a network's registered location. It is "
        "not the physical location of a person, and country centroid precision can "
        "be a thousand kilometres out.",
        "An IP address identifies an interface, not an individual. Shared relays, "
        "carrier NAT and compromised hosts all break that link.",
        "Personal data in this report is %s. Retention policy: %d days from case "
        "creation, after which message content is destroyed and the verdict, "
        "hashes, indicators and custody receipts are retained."
        % ("masked with a one-way format-preserving tag" if masking
           else "UNMASKED - handle as sensitive personal data", st.retention_days),
    ]})
    return b


# ---------------------------------------------------------------------------
# painting
# ---------------------------------------------------------------------------
def _paint_cover(cv: Any, block: Dict[str, Any], y: float) -> float:
    case: Case = block["case"]
    st = get_settings()
    cv.rect(MARGIN, y, CONTENT_W, 74, fill=PANEL)
    cv.rect(MARGIN, y, 4.0, 74, fill=ACCENT)
    cv.text(MARGIN + 14, y + 22, "MailTrace forensic report", 17, True, INK)
    cv.text(MARGIN + 14, y + 39, "%s  ·  %s" %
            (case.case_number, st.organisation), 10, False, MUTED)
    cv.text(
        MARGIN + 14,
        y + 55,
        "Email threat detection, geolocation and forensic "
        "intelligence",
        8.4,
        False,
        MUTED)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cv.text(MARGIN + 14, y + 67, "Generated %s" % stamp, 7.6, False, MUTED)
    y += 86
    tag = ("Contains masked personal data. Handle under the retention policy stated "
           "in section 16." if block["masking"] else
           "CONTAINS UNMASKED PERSONAL DATA. PII masking was disabled for this "
           "report; handle accordingly.")
    colour = MUTED if block["masking"] else SEVERITY_COLOUR[RISK_HIGH]
    for line in _wrap(cv, tag, CONTENT_W - 8, 7.8):
        cv.text(MARGIN, y, line, 7.8, False, colour)
        y += 10
    return y + 6


def _paint(cv: Any, blocks: Sequence[Dict[str, Any]], case: Case,
           total_pages: Optional[int]) -> int:
    """Lay the blocks out with pagination. Returns the page count."""
    page = 1
    y = MARGIN + 8

    def footer() -> None:
        label = ("Page %d of %d" % (page, total_pages)
                 ) if total_pages else "Page %d" % page
        cv.line(
            MARGIN,
            PAGE_H -
            MARGIN +
            6,
            PAGE_W -
            MARGIN,
            PAGE_H -
            MARGIN +
            6,
            0.5,
            RULE)
        cv.text(MARGIN, PAGE_H - MARGIN + 18,
                "MailTrace  ·  %s  ·  %s" % (case.case_number, cv.engine), 7.2,
                False, MUTED)
        w = cv.width_of(label, 7.2)
        cv.text(
            PAGE_W -
            MARGIN -
            w,
            PAGE_H -
            MARGIN +
            18,
            label,
            7.2,
            False,
            MUTED)

    def new_page() -> float:
        """Start a fresh page and return the new cursor position.

        Returning the cursor matters: the table and map painters keep their own
        local ``y``, and a page break that only updated this function's closure
        left them writing past the bottom margin forever, which turned a
        two-page table into a page per row.
        """
        nonlocal page, y
        footer()
        cv.new_page()
        page += 1
        y = MARGIN + 8
        return y

    def need(height: float) -> float:
        if y + height > PAGE_H - MARGIN - 22:
            return new_page()
        return y

    for block in blocks:
        kind = block["t"]
        if kind == "pagebreak":
            new_page()
        elif kind == "cover":
            y = _paint_cover(cv, block, y)
        elif kind == "h":
            y = need(30)
            y += 6
            cv.text(MARGIN, y + 10, block["text"], 11.4, True, INK)
            cv.line(MARGIN, y + 16, PAGE_W - MARGIN, y + 16, 0.8, ACCENT)
            y += 26
        elif kind == "p":
            size = block.get("size", 8.6)
            for line in _wrap(cv, block["text"], CONTENT_W, size):
                y = need(size + 4)
                cv.text(
                    MARGIN,
                    y + size,
                    line,
                    size,
                    False,
                    block.get(
                        "colour",
                        INK))
                y += size + 3.2
            y += 4
        elif kind == "banner":
            lines = _wrap(cv, block["text"], CONTENT_W - 16, 8.6, True)
            h = 8 + len(lines) * 12
            y = need(h + 6)
            cv.rect(MARGIN, y, CONTENT_W, h, fill=(0.99, 0.96, 0.90))
            cv.rect(MARGIN, y, 3.0, h, fill=block.get("colour", ACCENT))
            for i, line in enumerate(lines):
                cv.text(MARGIN + 12, y + 16 + i * 12, line, 8.6, True,
                        block.get("colour", INK))
            y += h + 8
        elif kind == "chips":
            y = need(40)
            x = MARGIN
            for label, value, colour in block["items"]:
                text = str(value)
                w = max(
                    cv.width_of(
                        text, 9.4, True), cv.width_of(
                        label, 6.8)) + 18
                if x + w > PAGE_W - MARGIN:
                    x = MARGIN
                    y += 40
                    y = need(40)
                cv.rect(x, y, w, 32, fill=WHITE, stroke=RULE)
                cv.rect(x, y, w, 2.4, fill=colour)
                cv.text(x + 8, y + 13, label.upper(), 6.4, False, MUTED)
                cv.text(x + 8, y + 26, text, 9.4, True, colour)
                x += w + 7
            y += 42
        elif kind == "kv":
            key_w = CONTENT_W * 0.30
            for k, val in block["rows"]:
                lines = _wrap(cv, str(val), CONTENT_W - key_w - 8, 8.4)
                h = max(12.0, len(lines) * 11.4)
                y = need(h + 2)
                cv.text(MARGIN, y + 9, str(k), 8.0, False, MUTED)
                for i, line in enumerate(lines):
                    cv.text(
                        MARGIN + key_w,
                        y + 9 + i * 11.4,
                        line,
                        8.4,
                        False,
                        INK)
                y += h + 1.6
            y += 6
        elif kind == "bullets":
            if block.get("label"):
                y = need(16)
                cv.text(MARGIN, y + 9, block["label"], 8.4, True, INK)
                y += 15
            for item in block["items"]:
                lines = _wrap(cv, str(item), CONTENT_W - 14, 8.2)
                y = need(len(lines) * 11 + 2)
                cv.circle(MARGIN + 3, y + 6, 1.4, fill=ACCENT)
                for i, line in enumerate(lines):
                    cv.text(MARGIN + 12, y + 9 + i * 11, line, 8.2, False, INK)
                y += len(lines) * 11 + 1.4
            y += 6
        elif kind == "table":
            y = _paint_table(cv, block, y, need, new_page)
        elif kind == "map":
            y = _paint_map(cv, block["layout"], y, need)
    footer()
    return page


def _paint_table(cv: Any,
                 block: Dict[str,
                             Any],
                 y: float,
                 need,
                 new_page) -> float:
    cols: List[Tuple[str, float, str]] = block["cols"]
    widths = [CONTENT_W * frac for _, frac, _ in cols]
    size = block.get("size", 7.8)
    sev_col = block.get("severity_col")

    def header(top: float) -> float:
        cv.rect(MARGIN, top, CONTENT_W, 15, fill=(0.925, 0.937, 0.957))
        x = MARGIN
        for (name, _frac, align), w in zip(cols, widths):
            label = name.upper()
            tx = x + 5 if align != "r" else x + \
                w - 5 - cv.width_of(label, 6.4, True)
            cv.text(tx, top + 10.5, label, 6.4, True, (0.28, 0.32, 0.40))
            x += w
        return top + 15

    y = header(need(46))
    for row_i, row in enumerate(block["rows"]):
        cells = [_wrap(cv, str(cell), w - 10, size)
                 for cell, w in zip(row, widths)]
        h = max(13.0, max(len(c) for c in cells) * (size + 2.6) + 5)
        if y + h > PAGE_H - MARGIN - 22:
            y = header(new_page())
        if row_i % 2 == 1:
            cv.rect(MARGIN, y, CONTENT_W, h, fill=ZEBRA)
        x = MARGIN
        for ci, ((_name, _frac, align), w) in enumerate(zip(cols, widths)):
            colour = INK
            if sev_col is not None and ci == sev_col:
                colour = SEVERITY_COLOUR.get(str(row[ci]).lower(), INK)
            for li, line in enumerate(cells[ci]):
                tx = x + 5 if align != "r" else x + \
                    w - 5 - cv.width_of(line, size)
                cv.text(tx, y + 9.5 + li * (size + 2.6), line, size,
                        colour is not INK, colour)
            x += w
        cv.line(MARGIN, y + h, PAGE_W - MARGIN, y + h, 0.4, RULE)
        y += h
    return y + 8


def _paint_map(cv: Any, lay: Dict[str, Any], y: float, need) -> float:
    """Draw the relay trace on a labelled graticule.

    There is no coastline. Bundling a world basemap would mean bundling somebody
    else's licensed geometry, and an outline traced by hand would be decoration
    pretending to be data. The graticule with degree labels lets a reader locate
    every marker precisely, and the country name is printed next to each dot, so
    nothing is lost except the illusion of a satellite view.
    """
    h = 214.0
    y = need(h + 80)
    x0, y0, w = MARGIN, y, CONTENT_W
    cv.rect(x0, y0, w, h, fill=(0.976, 0.984, 0.996), stroke=RULE)
    grat = lay["graticule"]
    for m in grat["meridians"]:
        gx = x0 + m["x"] * w
        cv.line(gx, y0, gx, y0 + h, 0.3, (0.88, 0.91, 0.95))
        # Degree labels sit *outside* the frame: inside, the bottom row of
        # meridian labels collided with the -60 parallel label and with any
        # marker plotted in the southern hemisphere.
        cv.text(gx + 1.5, y0 + h + 8, m["label"],
                5.4, False, (0.62, 0.66, 0.72))
    for pl in grat["parallels"]:
        gy = y0 + pl["y"] * h
        cv.line(x0, gy, x0 + w, gy, 0.3, (0.88, 0.91, 0.95))
        cv.text(x0 - 15, gy + 2, pl["label"], 5.4, False, (0.62, 0.66, 0.72))
    for seg in lay["segments"]:
        cv.line(x0 + seg["from"]["x"] * w, y0 + seg["from"]["y"] * h,
                x0 + seg["to"]["x"] * w, y0 + seg["to"]["y"] * h,
                0.9, (0.35, 0.52, 0.78), dash=(2.2, 1.8))
    for m in lay["markers"]:
        mx, my = x0 + m["x"] * w, y0 + m["y"] * h
        if m["kind"] == mapfig.KIND_ORIGIN:
            colour, r = SEVERITY_COLOUR[RISK_CRITICAL], 4.4
            cv.circle(mx, my, r + 2.6, stroke=colour, width=0.8)
        elif m["kind"] == mapfig.KIND_FINAL:
            colour, r = SEVERITY_COLOUR[RISK_CLEAN], 3.4
        else:
            colour, r = ACCENT, 3.0
        cv.circle(mx, my, r, fill=colour)
        label = "%s %s" % (m["index"], m["place"] or m["ip"])
        lx = mx + r + 3
        if lx + cv.width_of(label, 6.0) > x0 + w - 4:
            lx = mx - r - 3 - cv.width_of(label, 6.0)
        cv.text(lx, my + 2.2, label, 6.0, False, (0.20, 0.24, 0.32))
    y = y0 + h + 24
    legend = [("origin", SEVERITY_COLOUR[RISK_CRITICAL]), ("transit", ACCENT),
              ("delivery", SEVERITY_COLOUR[RISK_CLEAN])]
    lx = x0
    for name, colour in legend:
        cv.circle(lx + 3, y - 2, 3.0, fill=colour)
        cv.text(lx + 10, y, name, 6.8, False, MUTED)
        lx += cv.width_of(name, 6.8) + 26
    y += 12
    for line in _wrap(cv, "Projection: %s. %s Marker positions are network "
                          "registration locations, not physical addresses."
                          % (lay["projection"], lay["note"]), CONTENT_W, 6.8):
        cv.text(x0, y, line, 6.8, False, MUTED)
        y += 9
    return y + 6


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def engine_available() -> str:
    try:
        import reportlab  # noqa: F401,PLC0415

        return "reportlab"
    except ImportError:
        return "minipdf"


def build_report(case: Case,
                 path: Optional[str] = None,
                 engine: Optional[str] = None,
                 masking: Optional[bool] = None) -> Dict[str,
                                                         Any]:
    """Render the forensic report for ``case`` and return where it landed.

    ``engine`` forces a renderer; the default picks ReportLab when installed.
    ``masking`` overrides ``PII_MASKING`` for this document only - used when an
    analyst deliberately produces an unmasked copy for law enforcement, which the
    cover page then states in as many words.
    """
    st = get_settings()
    st.ensure_dirs()
    on = st.pii_masking if masking is None else bool(masking)
    chosen = engine or engine_available()
    target = path or str(Path(EVIDENCE_DIR) / ("%s.pdf" %
                         (case.case_number or case.id)))

    blocks = _blocks(case, on)
    # First pass counts pages so the footer can say "page 3 of 9" - a reader of a
    # printed forensic document needs to be able to tell a page is missing.
    counter = _NullCanvas()
    total = _paint(counter, blocks, case, None)

    if chosen == "reportlab":
        try:
            cv: Any = _ReportlabCanvas()
            cv.open(target)
        except Exception as exc:  # noqa: BLE001 - fall back rather than fail
            log.warning(
                "reportlab unavailable (%s); using the built-in writer", exc)
            chosen, cv = "minipdf", _MiniCanvas()
    else:
        cv = _MiniCanvas()
    pages = _paint(cv, blocks, case, total)
    out = cv.save(target)
    size = Path(out).stat().st_size if Path(out).exists() else 0
    case.report_path = out
    return {"path": out, "engine": chosen, "pages": pages, "bytes": size,
            "masked": on, "blocks": len(blocks)}
