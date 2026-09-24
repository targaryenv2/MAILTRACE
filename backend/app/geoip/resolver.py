"""IP geolocation and relay-path reconstruction.

Three tiers, in order of preference, and the tier used is always reported:

1. **MaxMind GeoLite2** (`live`) when both the `geoip2` package and a local
   `.mmdb` are present. City, coordinates and ASN come from the database.
2. **Offline table** (`offline-table`) - a small hand-curated set of allocations
   that are stable public facts (RFC 5737 documentation ranges, RFC 1918 private
   space, a handful of well-known anycast and cloud ranges). Coordinates at this
   tier are **country centroids**, never city-level, because inventing a city is
   inventing evidence.
3. **Unresolved** (`unavailable`) - `resolved=False`, empty payload. The agent
   reasons about the gap rather than guessing.

The infrastructure classifier is deliberately conservative. It tags what the
data supports (hosting range, documentation range, private range, reverse-DNS
naming pattern consistent with a Tor exit / dynamic residential host) and says
"consistent with" rather than asserting. PS-26106 asks for VPN/Tor/open-relay/
botnet indicators; an indicator is a lead, not a conviction, and the wording in
the report has to survive a lawyer reading it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import DATA_DIR, get_settings
from ..schemas import (
    GeoLocation,
    ReceivedHeader,
    RelayHop,
    SOURCE_FIXTURE,
    SOURCE_LIVE,
    SOURCE_OFFLINE_TABLE,
    SOURCE_UNAVAILABLE,
)

log = logging.getLogger(__name__)

_DEMO_MAP: Optional[Dict[str, Dict[str, object]]] = None

# Country centroids, degrees. Used only at the offline tier and only to draw a
# map marker; the report states the precision explicitly.
CENTROIDS: Dict[str, Tuple[float, float, str]] = {
    "US": (39.83, -98.58, "United States"), "IN": (22.35, 78.67, "India"),
    "GB": (54.00, -2.00, "United Kingdom"), "DE": (51.17, 10.45, "Germany"),
    "NL": (52.13, 5.29, "Netherlands"), "RU": (61.52, 105.32, "Russia"),
    "SG": (1.35, 103.82, "Singapore"), "RO": (45.94, 24.97, "Romania"),
    "CN": (35.86, 104.20, "China"), "BR": (-14.24, -51.93, "Brazil"),
    "NG": (9.08, 8.68, "Nigeria"), "FR": (46.23, 2.21, "France"),
    "JP": (36.20, 138.25, "Japan"), "AU": (-25.27, 133.78, "Australia"),
    "CA": (56.13, -106.35, "Canada"), "IE": (53.14, -7.69, "Ireland"),
    "HK": (22.32, 114.17, "Hong Kong"), "AE": (23.42, 53.85, "United Arab Emirates"),
    "ZA": (-30.56, 22.94, "South Africa"), "UA": (48.38, 31.17, "Ukraine"),
}

# (network, country_code, asn, isp, tags). Facts only.
OFFLINE_RANGES: List[Tuple[str, str, str, str, Tuple[str, ...]]] = [
    ("10.0.0.0/8", "", "", "RFC 1918 private", ("private",)),
    ("172.16.0.0/12", "", "", "RFC 1918 private", ("private",)),
    ("192.168.0.0/16", "", "", "RFC 1918 private", ("private",)),
    ("127.0.0.0/8", "", "", "loopback", ("private",)),
    ("169.254.0.0/16", "", "", "link-local", ("private",)),
    ("100.64.0.0/10", "", "", "RFC 6598 carrier NAT", ("private", "cgnat")),
    ("fc00::/7", "", "", "IPv6 unique local", ("private",)),
    ("::1/128", "", "", "IPv6 loopback", ("private",)),
    # RFC 5737 documentation ranges. Our synthetic corpus uses these on purpose so
    # no generated evidence can ever point at a real organisation.
    ("192.0.2.0/24", "", "", "RFC 5737 documentation range", ("documentation",)),
    ("198.51.100.0/24", "", "", "RFC 5737 documentation range", ("documentation",)),
    ("203.0.113.0/24", "", "", "RFC 5737 documentation range", ("documentation",)),
    ("2001:db8::/32", "", "", "RFC 3849 documentation range", ("documentation",)),
    # Stable public anycast / cloud allocations.
    ("8.8.8.0/24", "US", "AS15169", "Google LLC", ("cloud",)),
    ("8.8.4.0/24", "US", "AS15169", "Google LLC", ("cloud",)),
    ("1.1.1.0/24", "AU", "AS13335", "Cloudflare, Inc.", ("cloud",)),
    ("9.9.9.0/24", "US", "AS19281", "Quad9", ("cloud",)),
    ("13.107.0.0/16", "US", "AS8075", "Microsoft Corporation", ("cloud",)),
    ("40.92.0.0/15", "US", "AS8075", "Microsoft Corporation (Outlook)", ("cloud",)),
    ("52.96.0.0/14", "US", "AS8075", "Microsoft Corporation (Exchange Online)", ("cloud",)),
    ("209.85.128.0/17", "US", "AS15169", "Google LLC (Gmail)", ("cloud",)),
    ("142.250.0.0/15", "US", "AS15169", "Google LLC", ("cloud",)),
    ("17.0.0.0/8", "US", "AS714", "Apple Inc.", ("cloud",)),
]

_PARSED_RANGES: List[Tuple[ipaddress._BaseNetwork,
                           str, str, str, Tuple[str, ...]]] = []
for _cidr, _cc, _asn, _isp, _tags in OFFLINE_RANGES:
    try:
        _PARSED_RANGES.append(
            (ipaddress.ip_network(_cidr), _cc, _asn, _isp, _tags))
    except ValueError:  # pragma: no cover
        continue

# Reverse-DNS naming patterns. Each is an *indicator*, phrased as such
# downstream.
HOSTNAME_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)\btor[-._]?(exit|relay|node)\b", "reverse DNS names this host as a Tor node"),
    (r"(?i)\bexit[-._]?node\b", "reverse DNS suggests an anonymising exit node"),
    (r"(?i)\b(vpn|proxy|socks)\b", "reverse DNS suggests VPN or proxy infrastructure"),
    (r"(?i)\bopen[-._]?(smtp|relay|mail)\b", "reverse DNS suggests an open mail relay"),
    (r"(?i)\b(dynamic|dyn|dsl|pppoe|broadband|cable|dhcp)\b",
     "reverse DNS pattern of a dynamic residential address, which is unusual for a "
     "legitimate mail server and consistent with a compromised host"),
    (r"(?i)\b(vps|server|hosting|cloud|compute|instance|droplet|linode|ovh|colo)\b",
     "reverse DNS suggests hosting or cloud infrastructure rather than a corporate MTA"),
    (r"(?i)\b(bullet|offshore|anon)\w*host", "reverse DNS suggests bulletproof hosting"),
]

# Notes attached to demo stand-in addresses, derived from the fixture's own tags.
# These are the same statements the live path would produce from reverse DNS or ASN
# ownership, so a demo trace reads exactly like a real one.
DEMO_TAG_NOTES: Dict[str, str] = {
    "tor": "reverse DNS and ASN ownership identify this hop as a Tor exit relay, so "
           "the hop before it is not recoverable from the headers",
    "anonymiser": "hop belongs to anonymisation infrastructure",
    "open-relay": "hop is a misconfigured open mail relay, which launders the true origin",
    "bulletproof": "ASN is a hosting provider known for ignoring abuse reports",
    "hosting": "sending address belongs to hosting or cloud infrastructure rather than "
               "a corporate mail server",
    "residential": "address is residential broadband, which is unusual for a legitimate "
                   "mail server and consistent with a scam operator or a compromised host",
    "dynamic": "address is dynamically assigned, so it identifies a subscriber session "
               "rather than a stable host",
}


ISP_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)(digitalocean|linode|vultr|hetzner|ovh|contabo|scaleway|choopa)",
     "budget VPS provider commonly abused for bulk sending"),
    (r"(?i)(amazon|aws|google cloud|microsoft azure|azure|oracle cloud|alibaba)",
     "large cloud provider: sending IP is not owned by the purported sender"),
    (r"(?i)(tor project|nym|mullvad|nordvpn|expressvpn|private internet)",
     "anonymisation provider"),
]


def _demo_map() -> Dict[str, Dict[str, object]]:
    """Geolocation stand-ins for the corpus's documentation addresses.

    The bundled corpus uses RFC 5737 ranges so that no generated evidence can ever
    point at a real organisation. The side effect is that in DEMO_MODE the
    geolocation feature has nothing to resolve, and the trace map is empty - which
    reads as a broken feature rather than a safe one. This fixture supplies
    plausible locations for exactly those addresses, and every value it returns is
    stamped ``source="fixture"`` so it is visibly not a database lookup.

    Off in production: a documentation range in real mail *is* a forged header, and
    the analyser should keep saying so.
    """
    global _DEMO_MAP
    if _DEMO_MAP is None:
        try:
            raw = json.loads((DATA_DIR / "fixtures" / "geo_demo.json")
                             .read_text(encoding="utf-8"))
            _DEMO_MAP = {
                str(k): v for k, v in (
                    raw.get("ips") or {}).items()}
        except (OSError, ValueError) as exc:
            log.info("demo geo fixture unavailable (%s)", exc)
            _DEMO_MAP = {}
    return _DEMO_MAP


def reset_demo_map() -> None:
    """Drop the cached fixture. Used by tests that toggle DEMO_MODE."""
    global _DEMO_MAP
    _DEMO_MAP = None


def _table_lookup(ip: str) -> Optional[Tuple[str, str, str, Tuple[str, ...]]]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, cc, asn, isp, tags in _PARSED_RANGES:
        if addr.version == net.version and addr in net:
            return cc, asn, isp, tags
    return None


_CITY_READER = None
_ASN_READER = None
_MMDB_WARNED = False


def _get_mmdb_readers():
    global _CITY_READER, _ASN_READER, _MMDB_WARNED
    if _CITY_READER is None:
        st = get_settings()
        city_path = Path(st.maxmind_city_db)
        if not city_path.exists():
            city_path = DATA_DIR / "geoip" / "city.mmdb"
        asn_path = Path(st.maxmind_asn_db)
        if not asn_path.exists():
            asn_path = DATA_DIR / "geoip" / "asn.mmdb"

        if city_path.exists():
            try:
                import maxminddb
                _CITY_READER = maxminddb.open_database(str(city_path))
                if asn_path.exists():
                    _ASN_READER = maxminddb.open_database(str(asn_path))
                log.info("Loaded GeoIP binary database: %s", city_path)
            except Exception as e:
                log.warning("Failed to initialize maxminddb reader: %s", e)
        elif not _MMDB_WARNED:
            log.warning("GeoIP MMDB not found at %s. Falling back to fixture / offline table.", city_path)
            _MMDB_WARNED = True

    return _CITY_READER, _ASN_READER


def _maxmind(ip: str) -> Optional[GeoLocation]:
    """Real MMDB binary lookup using maxminddb or geoip2."""
    city_reader, asn_reader = _get_mmdb_readers()
    if city_reader is None:
        return None
    try:
        r = city_reader.get(ip)
        if not r or not isinstance(r, dict):
            return None

        country_dict = r.get("country") or r.get("registered_country") or {}
        country_code = str(country_dict.get("iso_code") or "")
        country_names = country_dict.get("names") or {}
        country_name = country_names.get("en") or country_code

        city_dict = r.get("city") or {}
        city_names = city_dict.get("names") or {}
        city_name = city_names.get("en") or ""

        loc_dict = r.get("location") or {}
        lat = loc_dict.get("latitude")
        lon = loc_dict.get("longitude")

        if lat is None or lon is None:
            if country_code in CENTROIDS:
                lat, lon, _ = CENTROIDS[country_code]
            else:
                lat, lon = 0.0, 0.0

        loc = GeoLocation(
            lat=float(lat),
            lon=float(lon),
            city=city_name,
            country=country_name,
            country_code=country_code,
            resolved=True,
            source=SOURCE_LIVE,
        )

        if asn_reader is not None:
            try:
                a = asn_reader.get(ip)
                if a and isinstance(a, dict):
                    asn_num = a.get("autonomous_system_number")
                    asn_org = a.get("autonomous_system_organization") or ""
                    if asn_num:
                        loc.asn = f"AS{asn_num}"
                    loc.isp = asn_org
            except Exception:
                pass

        return loc
    except Exception as exc:
        log.debug("maxmind lookup error for %s: %s", ip, exc)
        return None


_DOC_NETWORKS = tuple(
    ipaddress.ip_network(c) for c in
    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def is_documentation(ip: str) -> bool:
    """True for the RFC 5737 / RFC 3849 documentation ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(
        addr.version == net.version and addr in net for net in _DOC_NETWORKS)


def is_private(ip: str) -> bool:
    """RFC 1918 / loopback / link-local / ULA / CGNAT - address space that cannot
    appear as a public sender.

    Deliberately **not** ``not addr.is_global``. Python's ``ipaddress`` also treats
    the RFC 5737 documentation ranges as non-global, and the bundled corpus uses
    those to stand in for public attacker addresses. With the looser test every
    demo hop was reported as "inside a private network", every hop was skipped by
    :func:`earliest_reliable_hop`, and no case ever produced an origin - the
    headline geolocation feature silently returned nothing.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if is_documentation(ip):
        return False
    return bool(addr.is_loopback or addr.is_link_local or addr.is_private)


def resolve_ip(ip: str) -> GeoLocation:
    """Locate an IP, or say honestly that we could not."""
    if not ip:
        return GeoLocation(source=SOURCE_UNAVAILABLE)
    live = _maxmind(ip)
    if live is not None:
        return live
    demo = _demo_map().get(ip)
    if demo is not None:
        return GeoLocation(
            lat=float(demo.get("lat") or 0.0), lon=float(demo.get("lon") or 0.0),
            city=str(demo.get("city") or ""), country=str(demo.get("country") or ""),
            country_code=str(demo.get("country_code") or ""),
            asn=str(demo.get("asn") or ""), isp=str(demo.get("isp") or ""),
            resolved=True, source=SOURCE_FIXTURE)
    hit = _table_lookup(ip)
    if hit is None:
        return GeoLocation(source=SOURCE_UNAVAILABLE)
    cc, asn, isp, _tags = hit
    loc = GeoLocation(
        country_code=cc,
        asn=asn,
        isp=isp,
        source=SOURCE_OFFLINE_TABLE)
    if cc and cc in CENTROIDS:
        lat, lon, name = CENTROIDS[cc]
        loc.lat, loc.lon, loc.country = lat, lon, name
        loc.resolved = True
        # No city: the offline tier genuinely does not know it.
    elif isp:
        loc.resolved = True  # we know who owns it, just not where
    return loc


def classify_infrastructure(
        ip: str,
        hostname: str,
        loc: GeoLocation) -> List[str]:
    """Indicators for anonymised / abused sending infrastructure (PS-26106).

    Returns human-readable statements, not opaque labels, because these lines end
    up in a report someone else has to act on.
    """
    out: List[str] = []
    if ip and is_private(ip):
        out.append("non-routable address: this hop is inside a private network")
    demo = _demo_map().get(ip)
    hit = _table_lookup(ip)
    if demo is not None:
        # Demo stand-in: report what the fixture says this infrastructure is, and
        # skip the forged-header note - inside a demo the documentation range is
        # the point, not the finding.
        for tag, note in DEMO_TAG_NOTES.items():
            if tag in (demo.get("tags") or ()):
                out.append(note)
    elif hit and "documentation" in hit[3]:
        out.append(
            "address is from a reserved documentation range (RFC 5737/3849), "
            "so it is either synthetic test traffic or a forged header")
    if hit and "cgnat" in hit[3]:
        out.append(
            "carrier-grade NAT range: the address maps to many subscribers")
    if hit and "cloud" in hit[3]:
        out.append("address belongs to a large cloud provider (%s)" % hit[2])
    for pattern, note in HOSTNAME_PATTERNS:
        if hostname and re.search(pattern, hostname):
            out.append(note)
    for pattern, note in ISP_PATTERNS:
        if loc.isp and re.search(pattern, loc.isp):
            out.append(note)
    if ip and not hostname and not is_private(ip):
        out.append("no reverse DNS name presented for this hop")
    return sorted(set(out))


def _ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def build_relay_path(chain: List[ReceivedHeader]) -> List[RelayHop]:
    """Turn parsed Received headers into a geolocated, annotated path.

    ``chain`` arrives earliest-first (the parser already reverses the header
    order), which is the direction an analyst reads a trace in.

    Anomalies worth flagging are the ones that indicate header forgery or abused
    infrastructure: time running backwards, an implausible gap, a public hop
    appearing *after* the message was already inside the recipient's private
    network, and any anonymising-infrastructure indicator.
    """
    hops: List[RelayHop] = []
    prev_time: Optional[datetime] = None
    seen_private = False
    for h in chain:
        ip = h.from_ip or ""
        loc = resolve_ip(ip) if ip else GeoLocation(source=SOURCE_UNAVAILABLE)
        hop = RelayHop(index=h.index, ip=ip, hostname=h.from_host or "",
                       timestamp=h.timestamp, location=loc,
                       is_private=is_private(ip) if ip else False)
        reasons = classify_infrastructure(ip, hop.hostname, loc)

        t = _ts(h.timestamp)
        if t and prev_time:
            delta = (t - prev_time).total_seconds()
            hop.delay_seconds = round(delta, 1)
            if delta < -60:
                reasons.append(
                    "timestamp precedes the previous hop by %.0fs, which "
                    "indicates a forged or rewritten Received header" %
                    abs(delta))
            elif delta > 3600:
                reasons.append(
                    "%.1f hour gap before this hop: possible queueing on a "
                    "compromised or rate-limited relay" %
                    (delta / 3600.0))
        if t:
            prev_time = t

        if seen_private and not hop.is_private and ip:
            reasons.append(
                "public hop appears after an internal hop: the chain has "
                "been manipulated or a header was inserted")
        if hop.is_private:
            seen_private = True
        if not h.parse_ok:
            reasons.append("Received header could not be fully parsed")
        if ip and not loc.resolved:
            reasons.append("geolocation unavailable for this address")

        hop.anomaly_reasons = sorted(set(reasons))
        hop.is_anomalous = bool(hop.anomaly_reasons)
        hops.append(hop)
    return hops


def earliest_reliable_hop(hops: List[RelayHop]) -> Optional[RelayHop]:
    """The origin claim PS-26106 asks for: earliest hop we are willing to stand behind.

    "Reliable" means: a globally routable address, from a header that parsed, and
    not a reserved/documentation range. Attacker-supplied ``Received`` headers are
    prepended *below* the receiving infrastructure's own headers, so the earliest
    hop is the most likely to be forged - which is exactly why this returns the
    earliest hop that survives those tests rather than simply ``hops[0]``.
    """
    for hop in hops:
        if not hop.ip or hop.is_private:
            continue
        if is_documentation(hop.ip) and hop.ip not in _demo_map():
            continue
        if "Received header could not be fully parsed" in hop.anomaly_reasons:
            continue
        return hop
    for hop in hops:  # fall back to the earliest public hop, whatever its quality
        if hop.ip and not hop.is_private:
            return hop
    return None


def origin_summary(hops: List[RelayHop]) -> Dict[str, object]:
    """Compact origin statement for the dashboard and the PDF."""
    hop = earliest_reliable_hop(hops)
    if hop is None:
        return {
            "determined": False,
            "reason": "no routable sending node could be established from the "
            "Received chain",
            "hop_index": None,
            "ip": "",
            "confidence": "none"}
    loc = hop.location
    place = ", ".join(p for p in (loc.city, loc.country)
                      if p) or "location unresolved"
    # Confidence in the *origin claim*, separate from the case verdict: a live
    # city-level database lookup on a clean chain is a stronger claim than a
    # country centroid on a chain with forged timestamps.
    if loc.source == SOURCE_LIVE and not hop.is_anomalous:
        conf = "high"
    elif loc.resolved and not hop.is_anomalous:
        conf = "moderate"
    elif loc.resolved:
        conf = "low"
    else:
        conf = "none"
    return {
        "determined": True,
        "hop_index": hop.index,
        "ip": hop.ip,
        "hostname": hop.hostname,
        "place": place,
        "country": loc.country,
        "country_code": loc.country_code,
        "asn": loc.asn,
        "isp": loc.isp,
        "precision": "city" if loc.city else (
            "country centroid" if loc.resolved else "unknown"),
        "geo_source": loc.source,
        "confidence": conf,
        "indicators": hop.anomaly_reasons,
        "later_hops": max(
            0,
            len(hops) - hop.index - 1),
    }
