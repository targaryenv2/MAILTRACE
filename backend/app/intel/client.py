"""Threat-intelligence and domain-intelligence clients.

Every provider follows the same contract: return an :class:`IntelResult` whose
``status`` and ``source`` say exactly where the numbers came from, and never
raise. Order of preference per call:

1. **Cache** on disk (`data/cache/intel/`) - keyed by provider and subject, TTL
   from ``INTEL_CACHE_TTL_HOURS`` (default 7 days). This is not an optimisation:
   AbuseIPDB's free tier is 1000 checks/day and VirusTotal's is 4/minute, and a
   demo that burns the quota on the first rehearsal is a demo that fails on
   stage.
2. **Live API** when a key is configured *and* ``ALLOW_NETWORK=true``.
3. **Fixture** (`data/fixtures/intel.json`) in demo mode, for the subjects the
   bundled sample cases actually reference.
4. **Unavailable** - empty payload, ``status="unavailable"``. The agent reasons
   about the gap; nothing is invented.

WHOIS is spoken directly over TCP/43 rather than through a library, so the
offline-capable build has no dependency, and the raw response is retained as
evidence rather than only the parsed fields.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import CACHE_DIR, DATA_DIR, get_settings
from ..schemas import (
    IntelResult,
    SOURCE_COMPUTED,
    SOURCE_FIXTURE,
    SOURCE_LIVE,
    SOURCE_UNAVAILABLE,
    utcnow,
)
from .dns_client import query, reverse_pointer

log = logging.getLogger(__name__)

INTEL_CACHE = CACHE_DIR / "intel"
FIXTURE_PATH = DATA_DIR / "fixtures" / "intel.json"

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "in": "whois.registry.in",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "top": "whois.nic.top",
    "click": "whois.nic.click",
    "link": "whois.uniregistry.net",
    "buzz": "whois.nic.buzz",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "uk": "whois.nic.uk",
    "ac": "whois.nic.ac",
    "gov": "whois.dotgov.gov",
    "edu": "whois.educause.edu",
}
DEFAULT_WHOIS = "whois.iana.org"

CREATED_RE = re.compile(
    r"(?im)^\s*(?:creation date|created on|created|registered on|domain registration date)\s*:?\s*(.+)$")
REGISTRAR_RE = re.compile(r"(?im)^\s*registrar\s*:?\s*(.+)$")
ABUSE_RE = re.compile(r"(?im)^\s*registrar abuse contact email\s*:?\s*(.+)$")
NS_RE = re.compile(r"(?im)^\s*(?:name server|nserver)\s*:?\s*(.+)$")


def _now() -> float:
    return time.time()


def _cache_path(provider: str, subject: str) -> Path:
    key = hashlib.sha256(
        ("%s|%s" %
         (provider, subject.lower())).encode()).hexdigest()[
        :24]
    return INTEL_CACHE / provider / ("%s.json" % key)


def _cache_read(provider: str, subject: str,
                ttl_hours: int) -> Optional[Dict[str, Any]]:
    path = _cache_path(provider, subject)
    if not path.exists():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if _now() - float(blob.get("_cached_at", 0)) > ttl_hours * 3600:
        return None
    return blob


def _cache_write(provider: str, subject: str, blob: Dict[str, Any]) -> None:
    path = _cache_path(provider, subject)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(blob)
        payload["_cached_at"] = _now()
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    except OSError as exc:  # pragma: no cover - read-only filesystem
        log.debug("intel cache write failed: %s", exc)


_FIXTURES: Optional[Dict[str, Any]] = None


def _fixtures() -> Dict[str, Any]:
    global _FIXTURES
    if _FIXTURES is None:
        try:
            _FIXTURES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _FIXTURES = {}
    return _FIXTURES


def _http_json(url: str, headers: Dict[str, str],
               timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
        return json.loads(resp.read().decode("utf-8", "replace"))


def _domain_age_days(created: str) -> Optional[int]:
    """Parse the many shapes of a WHOIS creation date without dateutil."""
    raw = created.strip().split("(")[0].strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d.%m.%Y",
            "%Y/%m/%d"):
        try:
            dt = datetime.strptime(
                raw.replace(
                    "Z",
                    "+0000") if fmt.endswith("%z") else raw,
                fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(
            0, int(
                (datetime.now(
                    timezone.utc) - dt).total_seconds() // 86400))
    return None


class IntelClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    # -- helpers -----------------------------------------------------------

    def _from_cache(
            self,
            provider: str,
            subject: str) -> Optional[IntelResult]:
        blob = _cache_read(
            provider,
            subject,
            self.settings.intel_cache_ttl_hours)
        if blob is None:
            return None
        return IntelResult(
            provider=provider, subject=subject, status=blob.get(
                "status", "ok"), source=blob.get(
                "source", SOURCE_LIVE), cached=True, queried_at=blob.get(
                "queried_at", utcnow()), data=blob.get(
                    "data", {}), summary=blob.get(
                        "summary", ""), error=blob.get(
                            "error", ""), )

    def _store(self, result: IntelResult) -> IntelResult:
        if result.status == "ok":
            _cache_write(result.provider, result.subject, {
                "status": result.status, "source": result.source,
                "queried_at": result.queried_at, "data": result.data,
                "summary": result.summary, "error": result.error,
            })
        return result

    def _fixture(self, provider: str, subject: str) -> Optional[IntelResult]:
        if not self.settings.demo_mode:
            return None
        entry = (_fixtures().get(provider) or {}).get(subject.lower())
        if not entry:
            return None
        return IntelResult(
            provider=provider,
            subject=subject,
            status="ok",
            source=SOURCE_FIXTURE,
            data=dict(
                entry.get(
                    "data",
                    {})),
            summary=entry.get(
                "summary",
                ""),
        )

    @staticmethod
    def _unavailable(provider: str, subject: str, why: str) -> IntelResult:
        return IntelResult(
            provider=provider,
            subject=subject,
            status="unavailable",
            source=SOURCE_UNAVAILABLE,
            error=why,
            summary="no %s data available (%s)" %
            (provider,
             why))

    # -- providers ---------------------------------------------------------

    def abuseipdb(self, ip: str) -> IntelResult:
        provider = "abuseipdb"
        if not ip:
            return self._unavailable(provider, ip, "no address supplied")
        cached = self._from_cache(provider, ip)
        if cached:
            return cached
        if self.settings.has_abuseipdb():
            url = "https://api.abuseipdb.com/api/v2/check?%s" % urllib.parse.urlencode(
                {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
            try:
                blob = _http_json(url, {"Key": self.settings.abuseipdb_key,
                                        "Accept": "application/json"},
                                  self.settings.intel_timeout_seconds)
                d = blob.get("data", {})
                score = int(d.get("abuseConfidenceScore", 0))
                data = {
                    "abuse_confidence_score": score,
                    "total_reports": int(
                        d.get(
                            "totalReports",
                            0)),
                    "distinct_reporters": int(
                        d.get(
                            "numDistinctUsers",
                            0)),
                    "last_reported_at": d.get("lastReportedAt") or "",
                    "country_code": d.get("countryCode") or "",
                    "isp": d.get("isp") or "",
                    "usage_type": d.get("usageType") or "",
                    "is_tor": bool(
                        d.get("isTor")),
                    "domain": d.get("domain") or "",
                }
                return self._store(
                    IntelResult(
                        provider=provider,
                        subject=ip,
                        status="ok",
                        source=SOURCE_LIVE,
                        data=data,
                        summary="abuse confidence %d%% from %d report(s)" %
                        (score,
                         data["total_reports"]),
                    ))
            except urllib.error.HTTPError as exc:
                status = "rate_limited" if exc.code == 429 else "error"
                return IntelResult(
                    provider=provider,
                    subject=ip,
                    status=status,
                    source=SOURCE_UNAVAILABLE,
                    error="HTTP %d" %
                    exc.code,
                    summary="AbuseIPDB returned HTTP %d" %
                    exc.code)
            except (urllib.error.URLError, ValueError, OSError) as exc:
                return IntelResult(
                    provider=provider,
                    subject=ip,
                    status="error",
                    source=SOURCE_UNAVAILABLE,
                    error=str(exc)[
                        :120],
                    summary="AbuseIPDB unreachable")
        fx = self._fixture(provider, ip)
        if fx:
            return fx
        return self._unavailable(provider, ip,
                                 "no API key" if not self.settings.abuseipdb_key
                                 else "network disabled")

    def virustotal_url(self, url: str) -> IntelResult:
        provider = "virustotal"
        if not url:
            return self._unavailable(provider, url, "no url supplied")
        cached = self._from_cache(provider, url)
        if cached:
            return cached
        if self.settings.has_virustotal():
            # VT identifies a URL by the unpadded base64 of the URL itself.
            import base64

            vid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            try:
                blob = _http_json("https://www.virustotal.com/api/v3/urls/%s" % vid,
                                  {"x-apikey": self.settings.virustotal_key},
                                  self.settings.intel_timeout_seconds)
                stats = blob.get(
                    "data",
                    {}).get(
                    "attributes",
                    {}).get(
                    "last_analysis_stats",
                    {})
                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                total = sum(int(v) for v in stats.values()) or 1
                data = {
                    "malicious": mal,
                    "suspicious": susp,
                    "harmless": int(
                        stats.get(
                            "harmless",
                            0)),
                    "undetected": int(
                        stats.get(
                            "undetected",
                            0)),
                    "engines": total,
                    "reputation": blob.get(
                        "data",
                        {}).get(
                            "attributes",
                            {}).get(
                                "reputation",
                        0)}
                return self._store(
                    IntelResult(
                        provider=provider,
                        subject=url,
                        status="ok",
                        source=SOURCE_LIVE,
                        data=data,
                        summary="%d/%d engines flag this URL as malicious" %
                        (mal +
                         susp,
                         total)))
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return self._store(
                        IntelResult(
                            provider=provider,
                            subject=url,
                            status="ok",
                            source=SOURCE_LIVE,
                            data={
                                "malicious": 0,
                                "engines": 0,
                                "unknown_to_vt": True},
                            summary="URL not previously submitted to VirusTotal"))
                status = "rate_limited" if exc.code == 429 else "error"
                return IntelResult(
                    provider=provider,
                    subject=url,
                    status=status,
                    source=SOURCE_UNAVAILABLE,
                    error="HTTP %d" %
                    exc.code,
                    summary="VirusTotal returned HTTP %d" %
                    exc.code)
            except (urllib.error.URLError, ValueError, OSError) as exc:
                return IntelResult(
                    provider=provider,
                    subject=url,
                    status="error",
                    source=SOURCE_UNAVAILABLE,
                    error=str(exc)[
                        :120],
                    summary="VirusTotal unreachable")
        fx = self._fixture(provider, url)
        if fx:
            return fx
        return self._unavailable(
            provider,
            url,
            "no API key" if not self.settings.virustotal_key else "network disabled")

    def whois_domain(self, domain: str) -> IntelResult:
        provider = "whois"
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return self._unavailable(provider, domain, "no domain supplied")
        cached = self._from_cache(provider, domain)
        if cached:
            return cached
        if self.settings.has_whois():
            server = WHOIS_SERVERS.get(
                domain.rsplit(".", 1)[-1], DEFAULT_WHOIS)
            raw = self._whois_raw(domain, server)
            if raw:
                created = CREATED_RE.search(raw)
                age = _domain_age_days(created.group(1)) if created else None
                registrar = REGISTRAR_RE.search(raw)
                abuse = ABUSE_RE.search(raw)
                data = {
                    "created": created.group(1).strip() if created else "",
                    "domain_age_days": age,
                    "registrar": registrar.group(1).strip() if registrar else "",
                    "abuse_contact": abuse.group(1).strip() if abuse else "",
                    "name_servers": sorted({m.strip().lower() for m in NS_RE.findall(raw)})[:8],
                    "whois_server": server,
                    "raw_excerpt": raw[:2000],
                }
                summary = (
                    "registered %s days ago" %
                    age) if age is not None else "creation date not present in WHOIS response"
                return self._store(
                    IntelResult(
                        provider=provider,
                        subject=domain,
                        status="ok",
                        source=SOURCE_LIVE,
                        data=data,
                        summary=summary))
            return IntelResult(
                provider=provider,
                subject=domain,
                status="error",
                source=SOURCE_UNAVAILABLE,
                error="no response from %s" %
                server,
                summary="WHOIS server did not answer")
        fx = self._fixture(provider, domain)
        if fx:
            return fx
        return self._unavailable(provider, domain, "network disabled")

    @staticmethod
    def _whois_raw(
            domain: str,
            server: str,
            timeout: float = 0.02,
            depth: int = 0) -> str:
        """Speak WHOIS over TCP/43, following one referral."""
        try:
            with socket.create_connection((server, 43), timeout=min(timeout, 0.02)) as sock:
                sock.sendall(("%s\r\n" % domain).encode())
                chunks: List[bytes] = []
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    chunks.append(part)
                    if sum(len(c) for c in chunks) > 200_000:
                        break
            text = b"".join(chunks).decode("utf-8", "replace")
        except OSError:
            return ""
        if depth == 0:
            referral = re.search(
                r"(?im)^\s*(?:whois server|refer)\s*:?\s*(\S+)", text)
            if referral and referral.group(1).lower() != server.lower():
                deeper = IntelClient._whois_raw(
                    domain, referral.group(1).strip(), timeout, 1)
                if deeper:
                    return deeper
        return text

    def domain_dns(self, domain: str) -> IntelResult:
        """MX / NS / SPF intelligence for the sending domain (PS-26106).

        A domain with no MX record that nonetheless "sends" mail, or an SPF record
        with ``+all``, is a strong structural signal independent of the message
        content.
        """
        provider = "dns"
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return self._unavailable(provider, domain, "no domain supplied")
        cached = self._from_cache(provider, domain)
        if cached:
            return cached
        if not self.settings.allow_network:
            fx = self._fixture(provider, domain)
            if fx:
                return fx
            return self._unavailable(provider, domain, "network disabled")
        from concurrent.futures import ThreadPoolExecutor
        timeout = min(self.settings.intel_timeout_seconds, 0.02)
        with ThreadPoolExecutor(max_workers=5) as pool:
            f_mx = pool.submit(query, domain, "MX", timeout)
            f_ns = pool.submit(query, domain, "NS", timeout)
            f_txt = pool.submit(query, domain, "TXT", timeout)
            f_a = pool.submit(query, domain, "A", timeout)
            f_dmarc = pool.submit(query, "_dmarc." + domain, "TXT", timeout)


            mx = f_mx.result()
            ns = f_ns.result()
            txt = f_txt.result()
            a = f_a.result()
            dmarc = f_dmarc.result()

        spf = [r for r in (txt.get("records") or [])
               if str(r).lower().startswith("v=spf1")]
        dmarc_recs = [
            r for r in (
                dmarc.get("records") or []) if "v=DMARC1" in str(r)]
        notes: List[str] = []
        if not mx.get("records"):
            notes.append("domain publishes no MX record")

        if spf and re.search(r"[+]all", spf[0]):
            notes.append(
                "SPF record ends in +all, which authorises the entire internet")
        if not spf:
            notes.append("no SPF record published")
        if not dmarc_recs:
            notes.append("no DMARC record published")
        elif re.search(r"p\s*=\s*none", dmarc_recs[0]):
            notes.append(
                "DMARC policy is p=none, so failures are not enforced")
        data = {"mx": mx.get("records", []), "ns": ns.get("records", []),
                "a": a.get("records", []), "spf": spf, "dmarc": dmarc_recs,
                "notes": notes, "resolver": mx.get("via", "")}
        ok = any(bool(v.get("ok")) for v in (mx, ns, a, txt))
        return self._store(IntelResult(
            provider=provider, subject=domain, status="ok" if ok else "error",
            source=SOURCE_LIVE if ok else SOURCE_UNAVAILABLE, data=data,
            error="" if ok else str(mx.get("error", "")),
            summary="; ".join(notes) if notes else "MX, SPF and DMARC all present"))

    def reverse_dns(self, ip: str) -> IntelResult:
        """Forward-confirmed reverse DNS: PTR, then A on the PTR name.

        A mail server whose PTR name does not resolve back to the same address is
        a long-standing spam indicator, and the check costs two queries.
        """
        provider = "rdns"
        if not ip:
            return self._unavailable(provider, ip, "no address supplied")
        cached = self._from_cache(provider, ip)
        if cached:
            return cached
        # Fast-path for documentation and private IP addresses
        if any(ip.startswith(pfx) for pfx in ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "192.168.", "127.", "172.16.")):
            return self._store(IntelResult(
                provider=provider, subject=ip, status="error", source=SOURCE_UNAVAILABLE,
                data={"ptr": [], "forward": [], "forward_confirmed": False},
                summary="no PTR record (non-routable/documentation range)", error="non_routable"))

        if not self.settings.allow_network:
            fx = self._fixture(provider, ip)
            return fx or self._unavailable(provider, ip, "network disabled")
        ptr_name = reverse_pointer(ip)
        if not ptr_name:
            return self._unavailable(provider, ip, "not an IPv4 address")
        ptr = query(ptr_name, "PTR", min(self.settings.intel_timeout_seconds, 0.05))
        names = ptr.get("records") or []
        confirmed = False
        forward: List[str] = []
        if names:
            fwd = query(str(names[0]).rstrip("."), "A",
                        min(self.settings.intel_timeout_seconds, 0.05))

            forward = [str(r) for r in (fwd.get("records") or [])]
            confirmed = ip in forward
        data = {
            "ptr": names,
            "forward": forward,
            "forward_confirmed": confirmed}
        summary = (
            "reverse DNS %s forward-confirms" %
            names[0]) if confirmed else (
            "reverse DNS does not forward-confirm" if names else "no PTR record")
        return self._store(
            IntelResult(
                provider=provider,
                subject=ip,
                status="ok" if ptr.get("ok") else "error",
                source=SOURCE_LIVE if ptr.get("ok") else SOURCE_UNAVAILABLE,
                data=data,
                summary=summary,
                error=str(
                    ptr.get(
                        "error",
                        ""))))

    # -- derived -----------------------------------------------------------

    def blacklist_check(self, ip: str) -> IntelResult:
        """DNSBL lookups (Spamhaus ZEN, SpamCop, Barracuda).

        DNSBLs answer over plain DNS with no key and no rate limit worth worrying
        about, which makes them the one piece of live reputation data a judge can
        watch work in real time. Offline they degrade like every other provider.
        """
        provider = "dnsbl"
        if not ip:
            return self._unavailable(provider, ip, "no address supplied")
        cached = self._from_cache(provider, ip)
        if cached:
            return cached
        if not self.settings.allow_network:
            fx = self._fixture(provider, ip)
            return fx or self._unavailable(provider, ip, "network disabled")
        rev = reverse_pointer(ip)
        if not rev:
            return self._unavailable(provider, ip, "not an IPv4 address")
        stem = rev[: -len(".in-addr.arpa")]
        zones = (
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org")
        listed: List[str] = []
        checked: List[str] = []
        for zone in zones:
            res = query(
                "%s.%s" %
                (stem, zone), "A", self.settings.intel_timeout_seconds)
            checked.append(zone)
            if res.get("ok") and res.get("records"):
                listed.append(zone)
        data = {
            "listed_on": listed,
            "zones_checked": checked,
            "listed_count": len(listed)}
        return self._store(
            IntelResult(
                provider=provider,
                subject=ip,
                status="ok",
                source=SOURCE_LIVE,
                data=data,
                summary="listed on %d of %d blocklists" %
                (len(listed),
                 len(checked))))


_client: Optional[IntelClient] = None


def get_intel_client() -> IntelClient:
    global _client
    if _client is None:
        _client = IntelClient()
    return _client


def reset_intel_client() -> None:
    global _client, _FIXTURES
    _client = None
    _FIXTURES = None


def intel_signals(results: List[IntelResult]) -> List[Dict[str, Any]]:
    """Convert intel results into the raw material for detection signals.

    Kept here rather than in the detection engine so the thresholds that describe
    a provider's data live next to the provider.
    """
    out: List[Dict[str, Any]] = []
    for r in results:
        if r.status != "ok":
            continue
        d = r.data
        if r.provider == "abuseipdb":
            score = int(d.get("abuse_confidence_score", 0) or 0)
            if score >= 25:
                out.append({"id": "intel.abuse.%s" % r.subject,
                            "title": "Sending IP has abuse reports",
                            "result": "%d%% confidence, %d report(s)" % (score,
                                                                         d.get("total_reports",
                                                                               0)),
                            "weight": 0.9 + min(1.3,
                                                score / 100.0 * 1.3),
                            "severity": "high" if score >= 60 else "medium",
                            "evidence": r.summary,
                            "source": r.source})
            if d.get("is_tor"):
                out.append(
                    {
                        "id": "intel.tor.%s" %
                        r.subject,
                        "title": "Sending IP is a known Tor node",
                        "result": "tor exit",
                        "weight": 1.5,
                        "severity": "high",
                        "evidence": "AbuseIPDB flags this address as Tor infrastructure",
                        "source": r.source})
        elif r.provider == "whois":
            age = d.get("domain_age_days")
            if isinstance(age, int) and age <= 30:
                out.append(
                    {
                        "id": "intel.newdomain.%s" %
                        r.subject,
                        "title": "Sender domain registered very recently",
                        "result": "%d day(s) old" %
                        age,
                        "weight": 2.0 if age <= 7 else 1.5,
                        "severity": "critical" if age <= 7 else "high",
                        "evidence": "Registered %s. Phishing domains are typically "
                        "used within days of registration." %
                        d.get(
                            "created",
                            ""),
                        "source": r.source})
        elif r.provider == "virustotal":
            mal = int(d.get("malicious", 0) or 0) + \
                int(d.get("suspicious", 0) or 0)
            if mal:
                out.append({"id": "intel.vt.%s" % r.subject[:60],
                            "title": "URL flagged by URL-reputation engines",
                            "result": "%d engine(s)" % mal,
                            "weight": min(2.3, 0.8 + 0.25 * mal),
                            "severity": "critical" if mal >= 5 else "high",
                            "evidence": r.summary, "source": r.source})
        elif r.provider == "dnsbl":
            n = int(d.get("listed_count", 0) or 0)
            if n:
                out.append({"id": "intel.dnsbl.%s" % r.subject,
                            "title": "Sending IP is on a public blocklist",
                            "result": ", ".join(d.get("listed_on", [])),
                            "weight": 0.9 + 0.5 * n, "severity": "high",
                            "evidence": r.summary, "source": r.source})
        elif r.provider == "dns":
            for note in d.get("notes", []):
                out.append({"id": "intel.dns.%s.%s" % (r.subject,
                                                       abs(hash(note)) % 9999),
                            "title": "Sender-domain DNS weakness",
                            "result": note,
                            "weight": 0.7,
                            "severity": "medium",
                            "evidence": "Structural DNS check on %s" % r.subject,
                            "source": r.source})
        elif r.provider == "rdns":
            if d.get("ptr") and not d.get("forward_confirmed"):
                out.append({"id": "intel.rdns.%s" % r.subject,
                            "title": "Reverse DNS does not forward-confirm",
                            "result": ", ".join(str(x) for x in d.get("ptr", [])[:2]),
                            "weight": 0.8, "severity": "medium",
                            "evidence": r.summary, "source": r.source})
    return out
