"""Minimal DNS client over UDP, standard library only.

Why hand-rolled: `dnspython` is the obvious choice, but MailTrace has to run on a
freshly-cloned machine with nothing installed, and MX/TXT/A records are load
bearing evidence for PS-26106 (MX intelligence, SPF record retrieval, forward
confirmation of reverse DNS). Sixty lines of wire format is cheaper than a
dependency the demo machine might not have.

If `dnspython` *is* installed it is used instead - it handles EDNS, TCP fallback
and DNSSEC properly, and this module only implements the common path.
"""

from __future__ import annotations

import random
import socket
import struct
from typing import Dict, List, Optional, Tuple

QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28}
RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(
            ord(c) > 127 for c in label) else label.encode("ascii")
        if len(raw) > 63:
            raw = raw[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a possibly-compressed name. Returns (name, offset after the name)."""
    labels: List[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(data) or hops > 32:  # malformed or compression loop
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # pointer
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _build_query(name: str, qtype: int) -> Tuple[bytes, int]:
    tid = random.SystemRandom().randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1), tid


def _parse(data: bytes, tid: int) -> Tuple[int, List[Tuple[int, bytes, int]]]:
    if len(data) < 12:
        return -1, []
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != tid:
        return -1, []
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qd):
        _n, offset = _read_name(data, offset)
        offset += 4
    answers: List[Tuple[int, bytes, int]] = []
    for _ in range(an):
        _n, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(
            "!HHIH", data[offset:offset + 10])
        offset += 10
        answers.append((rtype, data[offset:offset + rdlen], offset))
        offset += rdlen
    return rcode, answers


_DNS_CACHE: Dict[Tuple[str, str], Dict[str, object]] = {}
_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local", ".internal", ".corp", ".onion")


def query(name: str, record: str = "A", timeout: float = 0.5,
          servers: Tuple[str, ...] = RESOLVERS) -> Dict[str, object]:
    """Resolve ``name``. Returns ``{"ok": bool, "records": [...], "error": str}``.

    Never raises: an unreachable resolver is a normal condition for this tool.
    """
    record = record.upper()
    cache_key = (name.lower().rstrip("."), record)
    if cache_key in _DNS_CACHE:
        return _DNS_CACHE[cache_key]

    # Fast-path for non-routable / RFC 2606 test domains to prevent socket timeouts
    clean_name = name.lower().rstrip(".")
    if any(clean_name.endswith(sfx) or clean_name == sfx[1:] for sfx in _RESERVED_SUFFIXES):
        res = {"ok": False, "records": [], "error": "reserved_domain", "via": "cached_mock"}
        _DNS_CACHE[cache_key] = res
        return res

    qtype = QTYPE.get(record)
    if qtype is None:
        return {
            "ok": False,
            "records": [],
            "error": "unsupported record type %s" %
            record}

    try:  # prefer the real library when it is available
        import dns.resolver  # type: ignore

        res = dns.resolver.Resolver()
        res.lifetime = min(timeout, 0.5)
        res.timeout = min(timeout, 0.5)

        answers = res.resolve(name, record)
        recs: List[str] = []
        for a in answers:
            if record == "MX":
                recs.append("%d %s" %
                            (a.preference, str(a.exchange).rstrip(".")))
            elif record == "TXT":
                recs.append(b"".join(a.strings).decode("utf-8", "replace"))
            else:
                recs.append(str(a).rstrip("."))
        return {
            "ok": True,
            "records": sorted(recs),
            "error": "",
            "via": "dnspython"}
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 - NXDOMAIN, timeout, no answer
        return {
            "ok": False,
            "records": [],
            "error": type(exc).__name__,
            "via": "dnspython"}

    payload, tid = _build_query(name, qtype)
    last = "no resolver reachable"
    for server in servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (server, 53))
            data, _ = sock.recvfrom(4096)
        except OSError as exc:
            last = "%s: %s" % (server, exc.__class__.__name__)
            continue
        finally:
            sock.close()
        rcode, answers = _parse(data, tid)
        if rcode == 3:
            return {
                "ok": False,
                "records": [],
                "error": "NXDOMAIN",
                "via": "udp/53"}
        if rcode != 0:
            last = "rcode %d" % rcode
            continue
        recs: List[str] = []
        for rtype, rdata, at in answers:
            if rtype == QTYPE["MX"] and len(rdata) >= 3:
                pref = struct.unpack("!H", rdata[:2])[0]
                host, _ = _read_name(data, at + 2)
                recs.append("%d %s" % (pref, host))
            elif rtype == QTYPE["TXT"]:
                parts: List[str] = []
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(
                        rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                recs.append("".join(parts))
            elif rtype == QTYPE["A"] and len(rdata) == 4:
                recs.append(socket.inet_ntoa(rdata))
            elif rtype == QTYPE["AAAA"] and len(rdata) == 16:
                recs.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (QTYPE["NS"], QTYPE["CNAME"], QTYPE["PTR"]):
                host, _ = _read_name(data, at)
                recs.append(host)
        return {
            "ok": True,
            "records": sorted(recs),
            "error": "",
            "via": "udp/53"}
    return {"ok": False, "records": [], "error": last, "via": "udp/53"}


def reverse_pointer(ip: str) -> Optional[str]:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    return None
