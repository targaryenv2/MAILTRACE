import json, os, sys
from pathlib import Path
import maxminddb

sys.stdout.reconfigure(encoding="utf-8")
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

print("=" * 70)
print("LAYER 4: GEOIP AUTHENTICITY")
print("=" * 70)

print("\n--- 4a. MMDB File Sizes ---")
city_path = REPO_ROOT / "data" / "geoip" / "city.mmdb"
asn_path = REPO_ROOT / "data" / "geoip" / "asn.mmdb"

print(f"city.mmdb exists: {city_path.exists()}")
if city_path.exists():
    print(f"city.mmdb size: {city_path.stat().st_size / 1e6:.2f} MB ({city_path.stat().st_size:,} bytes)")

print(f"asn.mmdb exists: {asn_path.exists()}")
if asn_path.exists():
    print(f"asn.mmdb size: {asn_path.stat().st_size / 1e6:.2f} MB ({asn_path.stat().st_size:,} bytes)")

print("\n--- 4b. Probing 5 Known IPs Against MMDB ---")
test_ips = {
    "8.8.8.8": "expected: Google, USA",
    "1.1.1.1": "expected: Cloudflare, Australia",
    "185.220.101.1": "expected: Tor exit node / Europe / Germany",
    "103.21.244.0": "expected: Cloudflare / Asia / Singapore",
    "41.58.0.1": "expected: Africa (Nigeria / Egypt region)",
}

with maxminddb.open_database(str(city_path)) as city_r, maxminddb.open_database(str(asn_path)) as asn_r:
    for ip, exp in test_ips.items():
        c_res = city_r.get(ip)
        a_res = asn_r.get(ip)
        country = c_res.get("country", {}).get("names", {}).get("en") if c_res else None
        city = c_res.get("city", {}).get("names", {}).get("en") if c_res else None
        asn = a_res.get("autonomous_system_number") if a_res else None
        org = a_res.get("autonomous_system_organization") if a_res else None
        print(f"\nIP: {ip} | Expected: {exp}")
        print(f"  City Result: country={country}, city={city}, loc={c_res.get('location') if c_res else None}")
        print(f"  ASN Result: AS{asn}, org={org}")

print("\n--- 4c. Resolver.py Resolution Output ---")
from app.geoip.resolver import resolve_ip

for ip, exp in test_ips.items():
    loc = resolve_ip(ip)
    print(f"IP {ip} -> resolved={loc.resolved}, source='{loc.source}', country={loc.country} ({loc.country_code}), city={loc.city}, asn={loc.asn}, isp='{loc.isp}'")

