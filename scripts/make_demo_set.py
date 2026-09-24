#!/usr/bin/env python3
"""Build the bundled demo set and its threat-intel fixtures.

The demo set is seven messages chosen from the generated corpus so that a
walkthrough hits every distinct code path: credential harvesting, text-only BEC,
a weaponised attachment, a consumer scam with an IP-literal link, the hard
AI-generated case, clean legitimate mail, and a malformed file that must degrade
rather than crash.

Fixtures: the demo messages deliberately use RFC 5737 documentation IPs and
reserved-style domains, so no real WHOIS, AbuseIPDB or VirusTotal record exists
for them and none can be fetched. The fixtures written here are therefore
**illustrative by construction** - every entry is stamped ``illustrative: true``,
served with ``source="fixture"``, and badged as such in the UI and the PDF. That
is the honest way to make an offline demo show the enrichment path working; the
alternative (inventing values and presenting them as live) is not acceptable in
an evidence tool.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))

from app.ingestion.parser import parse_eml, registrable  # noqa: E402

# (destination name, required tag, label filter)
WANTED = [
    ("01-phishing-password-expiry.eml", "credential-harvest", 1),
    ("02-bec-wire-transfer.eml", "bec", 1),
    ("03-dangerous-attachment.eml", "double-extension", 1),
    ("04-legitimate-notice.eml", "legitimate", 0),
    ("05-ai-generated-spearphish.eml", "ai-generated-style", 1),
    ("06-consumer-scam-ip-link.eml", "ip-literal-link", 1),
    ("07-malformed-headers.eml", "malformed", 1),
]

REGISTRARS = ["NameCheap, Inc.", "PDR Ltd. d/b/a PublicDomainRegistry.com",
              "Hostinger Operations UAB", "Alibaba Cloud Computing Ltd.",
              "GoDaddy.com, LLC", "Tucows Domains Inc."]


def _stable(seed: str, lo: int, hi: int) -> int:
    """Deterministic value in [lo, hi] from a string, so fixtures never churn."""
    h = 0
    for ch in seed:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return lo + (h % max(1, hi - lo + 1))


def pick(corpus: Path) -> List[Dict]:
    rows = [json.loads(l) for l in (corpus / "manifest.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    out: List[Dict] = []
    used: set = set()
    for dest, tag, label in WANTED:
        match: Optional[Dict] = None
        for r in rows:
            if r["file"] in used or int(r["label"]) != label:
                continue
            if tag in r.get("tags", []):
                match = r
                break
        if match is None:
            print("warning: no corpus message tagged %r" % tag)
            continue
        used.add(match["file"])
        row = dict(match)
        row["dest"] = dest
        out.append(row)
    return out


def build_fixtures(demo_dir: Path, rows: List[Dict]) -> Dict:
    whois: Dict[str, Dict] = {}
    abuse: Dict[str, Dict] = {}
    vt: Dict[str, Dict] = {}
    dns: Dict[str, Dict] = {}
    rdns: Dict[str, Dict] = {}
    dnsbl: Dict[str, Dict] = {}

    for row in rows:
        path = demo_dir / row["dest"]
        parsed = parse_eml(path.read_bytes(), path.name)
        bad = int(row["label"]) == 1
        dom = registrable(parsed.from_domain)
        if dom:
            age = _stable(dom, 2, 21) if bad else _stable(dom, 1400, 7000)
            whois[dom] = {"illustrative": True,
                          "data": {"created": "",
                                   "domain_age_days": age,
                                   "registrar": REGISTRARS[_stable(dom,
                                                                   0,
                                                                   len(REGISTRARS) - 1)],
                                   "abuse_contact": "abuse@%s" % REGISTRARS[_stable(dom,
                                                                                    0,
                                                                                    len(REGISTRARS) - 1)].split(",")[0] .lower().replace(" ",
                                                                                                                                         "").replace(".",
                                                                                                                                                     "-") + ".example",
                                   "name_servers": ["ns1.%s" % dom,
                                                    "ns2.%s" % dom],
                                   "whois_server": "fixture",
                                   },
                          "summary": "registered %d days ago (illustrative fixture)" % age,
                          }
            dns[dom] = {
                "illustrative": True,
                "data": {
                    "mx": [] if bad else ["10 mx1.%s" % dom],
                    "ns": ["ns1.%s" % dom, "ns2.%s" % dom],
                    "a": ["192.0.2.%d" % _stable(dom, 1, 250)],
                    "spf": [] if bad else ["v=spf1 include:_spf.%s -all" % dom],
                    "dmarc": [] if bad else ["v=DMARC1; p=reject; rua=mailto:dmarc@%s" % dom],
                    "notes": (["domain publishes no MX record", "no SPF record published",
                               "no DMARC record published"] if bad else []),
                    "resolver": "fixture",
                },
                "summary": ("no MX, SPF or DMARC published (illustrative fixture)" if bad
                            else "MX, SPF and DMARC all present (illustrative fixture)"),
            }
        ips = [h.from_ip for h in parsed.received_chain if h.from_ip]
        for ip in ips:
            score = _stable(ip, 55, 96) if bad else 0
            reports = _stable(ip + "r", 12, 240) if bad else 0
            abuse[ip] = {
                "illustrative": True,
                "data": {
                    "abuse_confidence_score": score,
                    "total_reports": reports,
                    "distinct_reporters": max(
                        1,
                        reports //
                        6) if reports else 0,
                    "last_reported_at": "",
                    "country_code": "",
                    "isp": "",
                    "usage_type": "Data Center/Web Hosting/Transit" if bad else "",
                    "is_tor": bool(
                        bad and "tor" in ip),
                    "domain": ""},
                "summary": "abuse confidence %d%% from %d report(s) (illustrative fixture)" %
                (score,
                 reports),
            }
            listed = ["zen.spamhaus.org", "b.barracudacentral.org"][: (
                1 if bad else 0)] + (["bl.spamcop.net"] if bad and score > 80 else [])
            dnsbl[ip] = {
                "illustrative": True,
                "data": {
                    "listed_on": listed,
                    "listed_count": len(listed),
                    "zones_checked": [
                        "zen.spamhaus.org",
                        "bl.spamcop.net",
                        "b.barracudacentral.org"]},
                "summary": "listed on %d of 3 blocklists (illustrative fixture)" %
                len(listed),
            }
            host = next((h.from_host for h in parsed.received_chain
                         if h.from_ip == ip and h.from_host), "")
            rdns[ip] = {
                "illustrative": True,
                "data": {"ptr": [host] if host else [], "forward": [] if bad else [ip],
                         "forward_confirmed": (not bad) and bool(host)},
                "summary": ("reverse DNS does not forward-confirm (illustrative fixture)"
                            if bad else "reverse DNS forward-confirms (illustrative fixture)"),
            }
        for u in parsed.urls[:6]:
            mal = _stable(u.url, 6, 21) if bad else 0
            vt[u.url.lower()] = {
                "illustrative": True,
                "data": {"malicious": mal, "suspicious": 1 if bad else 0,
                         "harmless": 0 if bad else 68, "undetected": 90 - mal,
                         "engines": 92, "reputation": -40 if bad else 0},
                "summary": "%d/92 engines flag this URL (illustrative fixture)" % mal,
            }

    return {
        "_README": (
            "Illustrative offline fixtures for the bundled demo set. The demo "
            "messages use RFC 5737 documentation IP ranges and reserved-style "
            "domains, so no real WHOIS/AbuseIPDB/VirusTotal record exists for them. "
            "Every entry is marked illustrative and is served with source='fixture' "
            "so the UI and the PDF badge it as non-live. Set ALLOW_NETWORK=true and "
            "supply API keys in .env to replace all of this with live lookups."),
        "_generated_by": "scripts/make_demo_set.py",
        "whois": whois, "abuseipdb": abuse, "virustotal": vt,
        "dns": dns, "rdns": rdns, "dnsbl": dnsbl,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(REPO / "data" / "corpus"))
    ap.add_argument("--demo", default=str(REPO / "data" / "demo"))
    args = ap.parse_args()
    corpus, demo = Path(args.corpus), Path(args.demo)
    demo.mkdir(parents=True, exist_ok=True)

    rows = pick(corpus)
    for row in rows:
        shutil.copyfile(corpus / row["file"], demo / row["dest"])
        print("%-38s <- %s" % (row["dest"], row["file"]))

    index = [{"file": r["dest"], "label": r["label"], "kind": r["kind"],
              "tags": r["tags"], "subject": r["subject"],
              "expected": "phishing" if r["label"] == 1 else "benign"} for r in rows]
    (demo / "index.json").write_text(json.dumps(index,
                                                indent=2, sort_keys=True) + "\n", encoding="utf-8")

    fixtures = build_fixtures(demo, rows)
    fx_path = REPO / "data" / "fixtures" / "intel.json"
    fx_path.parent.mkdir(parents=True, exist_ok=True)
    fx_path.write_text(
        json.dumps(
            fixtures,
            indent=2,
            sort_keys=True) +
        "\n",
        encoding="utf-8")
    counts = {k: len(v) for k, v in fixtures.items() if isinstance(v, dict)}
    print("fixtures -> %s %s" % (fx_path, counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
