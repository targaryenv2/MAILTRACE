"""Email ingestion: raw bytes in, a fully-populated ParsedEmail out.

Stdlib only. A malformed message must degrade to partial results rather than
raise, because "this .eml crashed the tool" is both a bad demo and a real
forensic failure: the attacker chooses the encoding.
"""

from __future__ import annotations

import base64
import binascii
import email
import email.policy
import hashlib
import html as html_mod
import ipaddress
import re
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

from ..schemas import (
    Attachment,
    AuthResult,
    ExtractedUrl,
    ParsedEmail,
    ReceivedHeader,
    SOURCE_COMPUTED,
)

# Shorteners are not malicious in themselves but they defeat URL inspection,
# which is why every mail-security product treats them as a signal.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "s.id", "bl.ink", "t.ly", "shorte.st", "adf.ly",
}

MACRO_EXT = {
    ".doc",
    ".docm",
    ".xls",
    ".xlsm",
    ".xlsb",
    ".ppt",
    ".pptm",
    ".dotm",
    ".xlam"}
EXEC_EXT = {
    ".exe",
    ".scr",
    ".com",
    ".pif",
    ".bat",
    ".cmd",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".hta",
    ".msi",
    ".msp",
    ".jar",
    ".ps1",
    ".lnk",
    ".cpl",
    ".dll",
    ".iso",
    ".img",
    ".vhd",
    ".apk",
}
ARCHIVE_EXT = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".cab",
    ".ace"}

# Magic-byte prefixes, so a file called invoice.pdf that is really a PE binary
# is reported as one. Order matters: longest distinctive prefix first.
MAGIC: List[Tuple[bytes, str]] = [
    (b"%PDF-", "pdf"),
    (b"MZ", "pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"PK\x03\x04", "zip-container"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xd0\xcf\x11\xe0", "ole2-office"),
    (b"\x1f\x8b", "gzip"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"{\\rtf", "rtf"),
    (b"#!", "script"),
]

URL_RE = re.compile(
    r"""(?xi)\b(?:https?://|ftp://|www\.)[^\s<>"'`\]\)\},]+""",
)
ANCHOR_RE = re.compile(
    r"""(?is)<a\b[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a\s*>"""
)
TAG_RE = re.compile(r"(?s)<(script|style).*?</\1\s*>|<[^>]+>")
# RFC 5321 "Received:" is famously loose; we pull the reliable pieces rather
# than pretending to fully parse it.
RECV_FROM_RE = re.compile(r"(?is)\bfrom\s+([^\s;()]+)")
RECV_BY_RE = re.compile(r"(?is)\bby\s+([^\s;()]+)")
RECV_WITH_RE = re.compile(r"(?is)\bwith\s+([A-Za-z0-9/._-]+)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
AUTH_KV_RE = re.compile(r"(?i)\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)")


def _decode(value: Optional[str]) -> str:
    """RFC 2047 decode, tolerating the broken encodings phishing kits emit."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        try:
            return value.encode(
                "latin-1",
                "replace").decode(
                "utf-8",
                "replace").strip()
        except Exception:
            return str(value).strip()


def _domain_of(addr: str) -> str:
    return addr.rsplit(
        "@", 1)[-1].strip().strip(">").lower() if "@" in addr else ""


def registrable(domain: str) -> str:
    """Best-effort eTLD+1 without the Public Suffix List.

    We keep three labels for the common two-part suffixes so ``foo.co.uk`` is
    not mistaken for ``co.uk``. This is an approximation and is documented as
    such: pulling in the full PSL is a dependency we deliberately avoid.
    """
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) < 3:
        return ".".join(parts)
    two = {
        "co",
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "ac",
        "or",
        "ne",
        "in",
        "res"}
    if parts[-2] in two and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def strip_html(raw: str) -> str:
    if not raw:
        return ""
    return html_mod.unescape(TAG_RE.sub(" ", raw))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _magic(data: bytes) -> str:
    for prefix, name in MAGIC:
        if data.startswith(prefix):
            return name
    return "unknown"


def _norm_url(raw: str) -> str:
    raw = raw.strip().rstrip(".,;:!?)\"']")
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    return raw


def _split_url(url: str) -> Tuple[str, str, str]:
    scheme, _, rest = url.partition("://")
    if not rest:
        scheme, rest = "http", url
    host, slash, path = rest.partition("/")
    host = host.split("@")[-1].split(":")[0].lower()
    return scheme.lower(), host, (slash + path)


def _make_url(
        raw: str,
        location: str,
        anchor_text: str = "") -> Optional[ExtractedUrl]:
    url = _norm_url(raw)
    if not url or url.lower().startswith(("mailto:", "tel:", "cid:", "data:")):
        return None
    scheme, host, path = _split_url(url)
    if not host:
        return None
    reasons: List[str] = []
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        reasons.append("host is a raw IP literal, not a domain name")
    except ValueError:
        pass
    puny = "xn--" in host
    if puny:
        reasons.append("internationalised (punycode) domain")
    reg = registrable(host)
    short = reg in SHORTENERS
    if short:
        reasons.append("URL shortener conceals the destination")
    if scheme == "http":
        reasons.append("plaintext http")
    if len(path) > 120:
        reasons.append("unusually long path")
    if re.search(
        r"(?i)(login|signin|verify|secure|account|update|password|mfa|otp)",
            path):
        reasons.append("credential-collection path keyword")
    mismatch = False
    if anchor_text:
        at = anchor_text.strip()
        if re.match(r"(?i)^(https?://|www\.)", at):
            _, at_host, _ = _split_url(_norm_url(at))
            mismatch = bool(at_host) and registrable(at_host) != reg
            if mismatch:
                reasons.append(
                    "visible link text points at a different domain")
    return ExtractedUrl(
        url=url,
        domain=host,
        scheme=scheme,
        path=path,
        location=location,
        anchor_text=anchor_text.strip()[:200],
        anchor_mismatch=mismatch,
        is_ip_literal=is_ip,
        is_punycode=puny,
        is_shortener=short,
        registrable_domain=reg,
        tld=host.rsplit(".", 1)[-1] if "." in host else "",
        reasons=reasons,
    )


def extract_urls(text: str, html: str) -> List[ExtractedUrl]:
    """Collect URLs from both parts, keeping anchor context where we have it."""
    out: List[ExtractedUrl] = []
    seen: set = set()

    for m in ANCHOR_RE.finditer(html or ""):
        href = m.group(1) or m.group(2) or m.group(3) or ""
        item = _make_url(
            html_mod.unescape(href),
            "anchor",
            strip_html(
                m.group(4) or ""))
        if item and (item.url, item.anchor_text) not in seen:
            seen.add((item.url, item.anchor_text))
            out.append(item)

    for source, label in (
            (text, "body_text"), (strip_html(html), "body_html")):
        for m in URL_RE.finditer(source or ""):
            item = _make_url(m.group(0), label)
            if item and (
                    item.url, "") not in seen and not any(
                    u.url == item.url for u in out):
                seen.add((item.url, ""))
                out.append(item)
    return out


def parse_received_chain(
        raw_headers: List[Tuple[str, str]]) -> List[ReceivedHeader]:
    """Turn ``Received:`` headers into an ordered hop list.

    Mail servers prepend, so the header list runs newest-first. We reverse it so
    index 0 is the earliest (closest to the true origin) hop, which is the one
    an investigator cares about. Private/reserved IPs are flagged rather than
    dropped: an internal-only chain is itself evidence about where a message
    entered the estate.
    """
    received = [v for (k, v) in raw_headers if k.lower() == "received"]
    hops: List[ReceivedHeader] = []
    for idx, raw in enumerate(reversed(received)):
        flat = " ".join(raw.split())
        hop = ReceivedHeader(index=idx, raw=flat[:600])
        fm = RECV_FROM_RE.search(flat)
        if fm:
            hop.from_host = fm.group(1).strip("[]();,")
        bm = RECV_BY_RE.search(flat)
        if bm:
            hop.by_host = bm.group(1).strip("[]();,")
        wm = RECV_WITH_RE.search(flat)
        if wm:
            hop.protocol = wm.group(1)
        # Prefer an IP inside brackets/parens (the peer address the MTA saw)
        # over any IP that happens to appear in a hostname.
        bracketed = re.findall(
            r"[\[\(]\s*(?:IPv6:)?([0-9a-fA-F:.]+)\s*[\]\)]", flat)
        cand = ""
        for b in bracketed:
            if IPV4_RE.fullmatch(b) or (":" in b and IPV6_RE.fullmatch(b)):
                cand = b
                break
        if not cand:
            m4 = IPV4_RE.search(flat)
            cand = m4.group(0) if m4 else ""
        if cand:
            try:
                ip = ipaddress.ip_address(cand)
                hop.from_ip = str(ip)
                hop.is_private_ip = not ip.is_global
            except ValueError:
                hop.parse_ok = False
        if ";" in flat:
            ts = flat.rsplit(";", 1)[1].strip()
            try:
                hop.timestamp = parsedate_to_datetime(ts).isoformat()
            except Exception:
                hop.timestamp = ""
                hop.parse_ok = False
        hops.append(hop)
    return hops


def parse_auth_results(raw_headers: List[Tuple[str, str]], from_domain: str,
                       return_path: str) -> AuthResult:
    """Read Authentication-Results and derive DMARC identifier alignment.

    A raw ``spf=pass`` says nothing about spoofing on its own: SPF authenticates
    the envelope sender, and an attacker controls that. Alignment against the
    visible ``From`` domain (RFC 7489 s3.1) is the check that matters, so we
    compute it rather than trusting the summary verdict.
    """
    res = AuthResult(from_domain=from_domain, source=SOURCE_COMPUTED)
    lowered = {k.lower(): v for k, v in raw_headers}
    ar_lines = [
        v for (
            k,
            v) in raw_headers if k.lower() in {
            "authentication-results",
            "arc-authentication-results",
            "x-forefront-antispam-report",
            "received-spf"}]
    res.raw_headers = [" ".join(v.split())[:400] for v in ar_lines]
    blob = " ".join(ar_lines)
    for key, value in AUTH_KV_RE.findall(blob):
        key, value = key.lower(), value.lower()
        if key == "spf" and res.spf == "unknown":
            res.spf = value
        elif key == "dkim" and res.dkim == "unknown":
            res.dkim = value
        elif key == "dmarc" and res.dmarc == "unknown":
            res.dmarc = value
        elif key == "arc":
            res.arc_chain = value
    if res.spf == "unknown" and "received-spf" in lowered:
        first = lowered["received-spf"].strip().split(
        )[0].lower() if lowered["received-spf"].strip() else ""
        if first:
            res.spf = first
    m = re.search(r"(?i)smtp\.mailfrom=([^\s;]+)", blob)
    env = _domain_of(m.group(1)) if m else _domain_of(return_path)
    res.envelope_from_domain = env
    res.spf_domain = env
    m = re.search(r"(?i)header\.(?:d|i)=([^\s;]+)", blob)
    if m:
        res.dkim_domain = _domain_of(
            m.group(1)) or m.group(1).lstrip("@").lower()
    if not res.dkim_domain and "dkim-signature" in lowered:
        dm = re.search(r"(?i)\bd=([^;\s]+)", lowered["dkim-signature"])
        if dm:
            res.dkim_domain = dm.group(1).lower()
            if res.dkim == "unknown":
                res.dkim = "present-unverified"
                res.parse_notes.append(
                    "DKIM-Signature present but no verifier result in headers"
                )
    m = re.search(r"(?i)\bp=(none|quarantine|reject)\b", blob)
    if m:
        res.dmarc_policy = m.group(1).lower()

    def aligned(candidate: str) -> Optional[bool]:
        if not candidate or not from_domain:
            return None
        return registrable(candidate) == registrable(from_domain)

    res.spf_aligned = aligned(res.spf_domain)
    res.dkim_aligned = aligned(res.dkim_domain)
    if res.dmarc == "unknown" and from_domain:
        # Derive DMARC the way a receiver would: pass requires an aligned pass
        # on at least one of SPF or DKIM.
        spf_ok = res.spf == "pass" and res.spf_aligned is True
        dkim_ok = res.dkim == "pass" and res.dkim_aligned is True
        if spf_ok or dkim_ok:
            res.dmarc = "pass"
            res.parse_notes.append(
                "DMARC derived from aligned SPF/DKIM result")
        elif res.spf != "unknown" or res.dkim != "unknown":
            res.dmarc = "fail"
            res.parse_notes.append(
                "DMARC derived: no aligned SPF or DKIM pass")
    return res


def _walk_bodies(msg: Message,
                 errors: List[str]) -> Tuple[str,
                                             str,
                                             List[Attachment]]:
    text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disp = (part.get_content_disposition() or "").lower()
        filename = _decode(part.get_filename() or "")
        try:
            payload = part.get_payload(decode=True)
        except (binascii.Error, AssertionError, ValueError) as exc:
            errors.append("undecodable part %s: %s" % (ctype, exc))
            payload = None
        if payload is None:
            raw = part.get_payload()
            payload = raw.encode(
                "utf-8",
                "replace") if isinstance(
                raw,
                str) else b""
        if disp == "attachment" or (
            filename and ctype not in {
                "text/plain",
                "text/html"}):
            attachments.append(_build_attachment(filename, ctype, payload))
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, "replace")
        except (LookupError, UnicodeDecodeError):
            decoded = payload.decode("utf-8", "replace")
            errors.append("unknown charset %r, fell back to utf-8" % charset)
        if ctype == "text/html":
            html_parts.append(decoded)
        elif ctype.startswith("text/"):
            text_parts.append(decoded)
        elif filename:
            attachments.append(_build_attachment(filename, ctype, payload))

    text = "\n".join(text_parts).strip()
    html = "\n".join(html_parts).strip()
    if not text and html:
        text = strip_html(html).strip()
    return text, html, attachments


def _build_attachment(filename: str, ctype: str, payload: bytes) -> Attachment:
    name = filename or "unnamed"
    lower = name.lower()
    ext = "." + lower.rsplit(".", 1)[1] if "." in lower else ""
    detected = _magic(payload[:16])
    notes: List[str] = []
    # A double extension is the oldest trick in the book and still works,
    # because Windows hides the known extension.
    double = bool(
        re.search(
            r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.[a-z0-9]{2,4}$",
            lower))
    if double:
        notes.append("double extension hides the real file type")
    mismatch = False
    if ext == ".pdf" and detected not in {"pdf", "unknown"}:
        mismatch = True
    if ext in {
        ".doc",
        ".xls",
        ".ppt"} and detected not in {
        "ole2-office",
            "unknown"}:
        mismatch = True
    if ext in {
        ".docx",
        ".xlsx",
        ".pptx"} and detected not in {
        "zip-container",
            "unknown"}:
        mismatch = True
    if detected in {"pe-executable", "elf-executable"} and ext not in EXEC_EXT:
        mismatch = True
        notes.append("content is an executable but the extension is not")
    if mismatch:
        notes.append(
            "declared extension %s does not match detected type %s" %
            (ext or "none", detected))
    return Attachment(
        filename=name,
        mime_type=ctype,
        size_bytes=len(payload),
        sha256=sha256_hex(payload),
        detected_type=detected,
        extension_mismatch=mismatch,
        is_archive=ext in ARCHIVE_EXT or detected in {
            "zip-container",
            "rar",
            "7z"},
        is_macro_capable=ext in MACRO_EXT,
        is_executable=ext in EXEC_EXT or detected in {
            "pe-executable",
            "elf-executable"},
        double_extension=double,
        notes=notes,
    )


def _detect_qr(attachments: List[Attachment],
               html: str) -> Tuple[bool, List[str]]:
    """Flag possible quishing without pretending to decode the image.

    Decoding needs an image library we refuse to hard-depend on, so we report
    the *possibility* (an inline image in a link-free credential-style mail)
    and leave the payload list empty rather than inventing a decoded URL.
    """
    image_like = [a for a in attachments if a.mime_type.startswith("image/")
                  or a.detected_type in {"png", "jpeg", "gif"}]
    inline_b64 = bool(re.search(r"(?i)<img[^>]+src=\"data:image/", html or ""))
    return (bool(image_like) or inline_b64), []


def parse_eml(raw: bytes, filename: str = "") -> ParsedEmail:
    """Parse a raw ``.eml``. Never raises on malformed input."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    errors: List[str] = []
    out = ParsedEmail(raw_sha256=sha256_hex(raw), size_bytes=len(raw))
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:  # pragma: no cover - defensive
        out.parse_complete = False
        out.parse_errors = ["could not parse message: %s" % exc]
        out.body_text = raw.decode("utf-8", "replace")[:20000]
        return out

    raw_headers: List[Tuple[str, str]] = []
    for k, v in msg.items():
        try:
            raw_headers.append((str(k), str(v)))
        except Exception:
            errors.append("unreadable header %r" % k)
    out.headers = [{"name": k, "value": _decode(
        v)[:1000]} for k, v in raw_headers]

    from_pairs = getaddresses(
        [v for (k, v) in raw_headers if k.lower() == "from"])
    if from_pairs:
        out.from_name = _decode(from_pairs[0][0])
        out.from_address = from_pairs[0][1].strip().lower()
        out.from_domain = _domain_of(out.from_address)
    out.to = [a.lower() for _, a in getaddresses(
        [v for k, v in raw_headers if k.lower() == "to"]) if a]
    out.cc = [a.lower() for _, a in getaddresses(
        [v for k, v in raw_headers if k.lower() == "cc"]) if a]
    out.bcc = [a.lower() for _, a in getaddresses(
        [v for k, v in raw_headers if k.lower() == "bcc"]) if a]
    rt = getaddresses([v for k, v in raw_headers if k.lower() == "reply-to"])
    out.reply_to = rt[0][1].strip().lower() if rt else ""
    rp = getaddresses(
        [v for k, v in raw_headers if k.lower() == "return-path"])
    out.return_path = rp[0][1].strip().lower() if rp else ""
    out.subject = _decode(msg.get("Subject", ""))
    out.message_id = (msg.get("Message-ID", "") or "").strip()
    date_raw = msg.get("Date", "")
    if date_raw:
        try:
            out.date = parsedate_to_datetime(date_raw).isoformat()
        except Exception:
            out.date = str(date_raw)
            errors.append("unparseable Date header")
    out.x_headers = {
        k: _decode(v)[
            :400] for k,
        v in raw_headers if k.lower().startswith("x-")}

    if not out.from_address and not out.subject and not raw_headers:
        errors.append("no readable headers found")

    text, html, attachments = _walk_bodies(msg, errors)
    out.body_text, out.body_html, out.attachments = text[:200000], html[:400000], attachments
    out.urls = extract_urls(out.body_text, out.body_html)
    out.received_chain = parse_received_chain(raw_headers)
    out.auth = parse_auth_results(
        raw_headers,
        out.from_domain,
        out.return_path)
    out.has_qr_code, out.qr_payloads = _detect_qr(attachments, out.body_html)
    if not out.body_text and not out.body_html:
        errors.append("no readable body content")
    out.parse_errors = errors
    out.parse_complete = not errors
    return out


def fingerprint(parsed: ParsedEmail) -> str:
    """Campaign fingerprint: same actor, same lure, different recipient.

    Deliberately excludes recipient and Message-ID so that 200 copies of one
    campaign collapse to a single cluster, and normalises the subject so
    "Invoice 8821" and "Invoice 8822" still group.
    """
    subject = re.sub(r"\d+", "#", (parsed.subject or "").lower()).strip()
    subject = re.sub(r"\s+", " ", subject)
    domains = sorted(
        {u.registrable_domain for u in parsed.urls if u.registrable_domain})
    basis = "|".join([
        parsed.from_domain,
        parsed.from_name.lower().strip(),
        subject,
        ",".join(domains),
        ",".join(sorted(a.sha256 for a in parsed.attachments)),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def b64_preview(data: bytes, limit: int = 48) -> str:
    return base64.b64encode(data[:limit]).decode("ascii")


def header_map(parsed: ParsedEmail) -> Dict[str, str]:
    return {h["name"].lower(): h["value"] for h in parsed.headers}
