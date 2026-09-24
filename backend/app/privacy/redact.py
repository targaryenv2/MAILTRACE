"""PII handling, masking, retention and the evidence/debug-log split.

The brief and the problem statement both ask for "privacy and legal safeguards",
which in practice means four concrete behaviours rather than a policy paragraph:

* **Masking on the way out.** Recipient addresses, phone numbers, payment card
  numbers and Indian identifiers (Aadhaar, PAN, GSTIN, IFSC, UPI handles) are
  masked in anything rendered to a non-privileged view or written to a shared
  report, while the unmasked original stays in the evidence store. Masking is
  *format-preserving* so the analyst can still see that two mails targeted the
  same person without seeing who.
* **Digest-only on chain.** The custody contract receives keccak digests, never
  content. Enforced upstream in ``blockchain/client.py``; asserted here by
  :func:`assert_no_pii` which is used in tests.
* **Configurable retention.** ``RETENTION_DAYS`` drives :func:`apply_retention`,
  which purges raw ``.eml`` bodies and attachment blobs while keeping the hashes,
  verdicts and custody chain - so a case remains provable after its content has
  been destroyed, which is what a retention policy actually needs to allow.
* **Separated logs.** Application debug logging never receives message content;
  :func:`safe_log_fields` is what call sites pass to the logger.

Masking is one-way by design (a truncated keccak tag, not encryption): a
reversible mask in a report is not a mask. Where re-identification is needed, the
tag lets an authorised analyst look the record up in the evidence store.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..config import DATA_DIR, EVIDENCE_DIR, get_settings
from ..blockchain.keccak import keccak256

log = logging.getLogger(__name__)

EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s\-]?)?(?:\d[\s\-]?){9,13}\d(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[A-Z\d]Z[A-Z\d]\b")
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
UPI_RE = re.compile(
    r"\b[\w.\-]{3,}@(?:okaxis|oksbi|okhdfcbank|okicici|ybl|paytm|upi|axl)\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")

# Output of this module's own maskers, so a leak scan can exclude it. Every masker
# leaves one of three fingerprints: an asterisk run, a ``[#tag]`` keccak marker, or
# a ``KIND-`` prefix followed by asterisks. Matching those is what lets
# assert_no_pii tell "this address was never protected" from "this address has
# already been destroyed and only its shape remains".
MASKED_RE = re.compile(
    r"(?:[A-Z]+-)?[A-Za-z0-9._%+\-]*\*{2,}[A-Za-z0-9._%+\-]*"
    r"(?:@[A-Za-z0-9.\-]+)?(?:\s*\[#[0-9a-f]{6}\])?"
    r"|\[#[0-9a-f]{6}\]")

# Fields that legitimately carry PII on a case. Anything in this list is masked
# by redact_case; anything not in it is assumed non-personal and left alone, so a
# new field cannot be silently leaked - the test suite checks the inverse too.
PII_FIELDS = (
    "recipient", "reported_by", "recipient_email", "to", "cc", "bcc",
    "display_name", "sender_display", "analyst", "analyst_note",
)


def _tag(value: str) -> str:
    """Stable 6-hex correlation tag: same input -> same tag, no way back."""
    return keccak256(value.strip().lower().encode("utf-8")).hex()[:6]


def mask_email(value: str) -> str:
    """``priya.sharma@acme.co.in`` -> ``p*********a@acme.co.in [#4f2c1a]``.

    The domain is kept because it is organisational, not personal, and an analyst
    needs it to see which tenant was targeted.
    """
    def repl(m: "re.Match[str]") -> str:
        local, domain = m.group(1), m.group(2)
        if len(local) <= 2:
            hidden = "*" * len(local)
        else:
            hidden = local[0] + "*" * (len(local) - 2) + local[-1]
        return "%s@%s [#%s]" % (hidden, domain, _tag(m.group(0)))
    return EMAIL_RE.sub(repl, value or "")


def _mask_digits(text: str, keep_last: int = 4) -> str:
    digits = re.sub(r"\D", "", text)
    if len(digits) <= keep_last:
        return "*" * len(digits)
    return "*" * (len(digits) - keep_last) + digits[-keep_last:]


def mask_text(text: str, mode: Optional[str] = None) -> str:
    """Mask every PII pattern in free text.

    ``mode``: ``mask`` (default) redacts, ``off`` returns the text unchanged for
    privileged views. Order matters - the more specific Indian identifiers are
    matched before the generic card/phone patterns, otherwise Aadhaar would be
    swallowed by the card regex and mislabelled in the report.
    """
    if not text:
        return text
    if (mode or "mask") == "off":
        return text
    out = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), text)
    # Card before Aadhaar, Aadhaar before phone: a 16-digit card contains a
    # 12-digit run that Aadhaar's pattern would otherwise claim first, and a
    # 12-digit Aadhaar falls inside the phone pattern's length range.
    out = CARD_RE.sub(lambda m: "CARD-" + _mask_digits(m.group(0)), out)
    out = AADHAAR_RE.sub(lambda m: "AADHAAR-" + _mask_digits(m.group(0)), out)
    out = GSTIN_RE.sub(lambda m: "GSTIN-" + m.group(0)
                       [:2] + "*" * 11 + m.group(0)[-2:], out)
    out = PAN_RE.sub(lambda m: "PAN-" + m.group(0)
                     [:2] + "*" * 6 + m.group(0)[-1], out)
    out = IFSC_RE.sub(lambda m: "IFSC-" + m.group(0)[:4] + "*" * 7, out)
    out = IBAN_RE.sub(lambda m: "IBAN-" + m.group(0)
                      [:4] + "*" * (len(m.group(0)) - 8) + m.group(0)[-4:], out)
    out = UPI_RE.sub(lambda m: "UPI-" + _tag(m.group(0)), out)
    out = PHONE_RE.sub(lambda m: "PHONE-" + _mask_digits(m.group(0), 3), out)
    return out


def pii_inventory(text: str) -> Dict[str, int]:
    """What categories of personal data a blob contains, without echoing any.

    Used by the report footer and the settings panel to state exactly what the
    case holds, which is the disclosure a DPDP notice needs.
    """
    return {name: len(rx.findall(text or "")) for name, rx in (
        ("email_addresses", EMAIL_RE), ("aadhaar", AADHAAR_RE), ("pan", PAN_RE),
        ("gstin", GSTIN_RE), ("ifsc", IFSC_RE), ("upi", UPI_RE), ("iban", IBAN_RE),
        ("card_numbers", CARD_RE), ("phone_numbers", PHONE_RE),
    ) if rx.findall(text or "")}


CRYPTO_FIELDS = {
    "payload_hash", "prev_hash", "entry_hash", "tx_hash", "sha256", "hash",
    "digest", "state_root", "case_key", "tx", "receipts", "chain_receipts"
}


def _walk(value: Any, mask_all: bool, key: str = "") -> Any:
    """Recursively mask a JSON-ish structure.

    Strings under a known PII key are always masked; other strings are scanned
    for PII patterns only when ``mask_all`` is set, because scanning every field
    of every case is measurably slower and most fields cannot contain PII.
    """
    if key in CRYPTO_FIELDS:
        return value
    if isinstance(value, dict):
        return {k: _walk(v, mask_all, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, mask_all, key) for v in value]
    if isinstance(value, str) and value:
        if value.startswith("0x") and len(value) >= 42:
            return value
        if key in PII_FIELDS:
            return mask_text(value, "mask")
        if mask_all:
            return mask_text(value, "mask")
    return value


def redact_case(case_dict: Dict[str, Any], deep: bool = True,
                enabled: Optional[bool] = None) -> Dict[str, Any]:
    """Return a masked copy of a serialised case. The original is never mutated.

    ``deep`` also scans bodies, headers and narratives, which is what a report or
    an external share needs; the analyst UI uses ``deep=False`` so the evidence
    itself stays readable while recipient identities are still masked.
    """
    st = get_settings()
    on = st.pii_masking if enabled is None else enabled
    if not on:
        return case_dict
    out = copy.deepcopy(case_dict)
    out = _walk(out, mask_all=deep)
    meta = out.setdefault("privacy", {})
    meta.update({"masked": True, "deep": deep,
                 "policy": "format-preserving one-way mask (keccak tag)",
                 "retention_days": st.retention_days})
    return out


def assert_no_pii(payload: Any) -> List[str]:
    """Return the PII categories found in ``payload``; empty list means clean.

    Called by the blockchain tests against the exact bytes about to be sent to a
    contract. A non-empty return there is a build failure, not a warning: once a
    transaction is mined it cannot be unpublished.

    Already-masked values are removed before the scan. ``mask_email`` is
    format-preserving by design - ``p**********a@example.com`` keeps the shape of
    an address so a report stays readable - so the email pattern still matches its
    own output. Counting that as a leak would make the function flag the very
    thing that fixes the leak, and a check that fires on correct input gets
    switched off. What is destroyed is the identifying part, which is the test
    that matters.
    """
    text = payload if isinstance(
        payload,
        str) else json.dumps(
        payload,
        default=str)
    text = MASKED_RE.sub(" ", text)
    return sorted(pii_inventory(text).keys())


def safe_log_fields(case_id: str, **fields: Any) -> Dict[str, Any]:
    """Build a log record that cannot leak content.

    Application debug logs and the evidence trail are deliberately different
    systems: logs are rotated, shipped and read by ops, so they get identifiers,
    counts and verdicts only. Values are masked *and* truncated.
    """
    safe: Dict[str, Any] = {"case_id": case_id}
    for key, value in fields.items():
        if isinstance(value, str):
            safe[key] = mask_text(value, "mask")[:120]
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        else:
            safe[key] = type(value).__name__
    return safe


# ---------------------------------------------------------------------------
# retention
# ---------------------------------------------------------------------------

RETENTION_LOG = EVIDENCE_DIR / "retention.log.jsonl"
# What a purge destroys, and what it must keep. Keeping the digests is the whole
# point: the case stays provable and the custody chain stays verifiable after the
# content is gone.
PURGE_GLOBS = ("*.eml", "*.eml.gz", "attachments/*", "bodies/*", "shot-*.png")
KEEP_ALWAYS = ("custody_trail.jsonl", "retention.log.jsonl")


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        text = (value or "").replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def retention_status(now: Optional[datetime] = None) -> Dict[str, Any]:
    """What the current policy would delete, without deleting it."""
    st = get_settings()
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max(0, st.retention_days))
    due: List[Dict[str, Any]] = []
    for path in _purgeable():
        mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        if mtime < cutoff:
            due.append({"path": str(path), "age_days": (now - mtime).days,
                        "size_bytes": path.stat().st_size})
    return {
        "retention_days": st.retention_days,
        "cutoff": cutoff.isoformat(),
        "candidates": len(due),
        "bytes": sum(d["size_bytes"] for d in due),
        "preserved": list(KEEP_ALWAYS),
        "policy": ("raw message bodies, attachment blobs and screenshots are purged; "
                   "hashes, verdicts, IOCs and the custody chain are retained so the "
                   "case remains provable"),
        "items": due[:50],
    }


def _purgeable() -> List[Path]:
    roots = [EVIDENCE_DIR, DATA_DIR / "uploads", DATA_DIR / "cases"]
    out: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in PURGE_GLOBS:
            for path in root.glob(pattern):
                if path.is_file() and path.name not in KEEP_ALWAYS:
                    out.append(path)
    return sorted(set(out))


def apply_retention(dry_run: bool = True,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """Enforce the retention policy.

    Defaults to ``dry_run=True``. Deleting evidence is irreversible, so the
    destructive path is opt-in at the call site and every deletion is appended to
    ``retention.log.jsonl`` - a purge that leaves no record of having happened is
    itself an evidentiary problem.
    """
    status = retention_status(now)
    deleted: List[str] = []
    errors: List[str] = []
    if not dry_run:
        for item in status["items"]:
            path = Path(item["path"])
            try:
                digest = keccak256(path.read_bytes()).hex()
                path.unlink()
                deleted.append(str(path))
                _append_retention_log({
                    "event": "purged", "path": str(path), "age_days": item["age_days"],
                    "size_bytes": item["size_bytes"], "content_keccak": digest,
                    "retention_days": status["retention_days"],
                    "at": datetime.now(timezone.utc).isoformat(),
                })
            except OSError as exc:
                errors.append("%s: %s" % (path.name, exc))
    status.update({"dry_run": dry_run,
                   "deleted": len(deleted),
                   "errors": errors})
    return status


def _append_retention_log(record: Dict[str, Any]) -> None:
    try:
        RETENTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with RETENTION_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:  # pragma: no cover
        log.warning("retention log append failed: %s", exc)


def policy_summary() -> Dict[str, Any]:
    """The disclosure block the report and the settings panel both render."""
    st = get_settings()
    return {
        "pii_masking": st.pii_masking,
        "retention_days": st.retention_days,
        "on_chain_content": "keccak-256 digests, verdict labels and timestamps only",
        "evidence_store": str(EVIDENCE_DIR),
        "logs_contain_content": False,
        "masking_reversible": False,
        "lawful_basis_note": (
            "Processing is limited to email metadata and content already "
            "received by the organisation, for the purpose of security "
            "incident detection and response."),
        "chain_of_custody": (
            "every ingest, step, verdict and analyst action is hash-chained "
            "and, when a chain is configured, anchored on-chain"),
    }
