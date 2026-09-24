#!/usr/bin/env python3
"""Download real City and ASN MMDB databases for MaxMind-compatible binary lookups.

Downloads from free db-ip.com and public GitHub GeoLite2 binary mirrors,
decompressing into data/geoip/city.mmdb and data/geoip/asn.mmdb.
"""

from __future__ import annotations

import gzip
import logging
import sys
from datetime import datetime
from pathlib import Path
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("download_geoip")

REPO_ROOT = Path(__file__).resolve().parent.parent
GEOIP_DIR = REPO_ROOT / "data" / "geoip"


def _download_file(urls: list[str], target_path: Path, is_gzip: bool = False) -> bool:
    if target_path.exists() and target_path.stat().st_size > 100_000:
        log.info(f"{target_path.name} already exists ({target_path.stat().st_size / 1_000_000:.1f} MB). Skipping.")
        return True

    target_path.parent.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "MailTrace-Forensics/1.0"}

    for url in urls:
        try:
            log.info(f"Attempting download from {url}...")
            resp = requests.get(url, headers=headers, timeout=30, stream=True)
            if resp.status_code == 200:
                temp_file = target_path.with_suffix(".tmp")
                if is_gzip or url.endswith(".gz"):
                    with gzip.GzipFile(fileobj=resp.raw) as gz, open(temp_file, "wb") as f_out:
                        while chunk := gz.read(64 * 1024):
                            f_out.write(chunk)
                else:
                    with open(temp_file, "wb") as f_out:
                        for chunk in resp.iter_content(chunk_size=64 * 1024):
                            if chunk:
                                f_out.write(chunk)
                
                if temp_file.exists() and temp_file.stat().st_size > 50_000:
                    temp_file.replace(target_path)
                    log.info(f"Successfully saved {target_path} ({target_path.stat().st_size / 1_000_000:.1f} MB)")
                    return True
                else:
                    if temp_file.exists():
                        temp_file.unlink()
        except Exception as e:
            log.warning(f"Failed from {url}: {e}")
            continue

    log.error(f"Could not download {target_path.name} from any mirror.")
    return False


def main() -> int:
    now = datetime.now()
    ym = now.strftime("%Y-%m")
    prev_m = f"{now.year}-{now.month-1:02d}" if now.month > 1 else f"{now.year-1}-12"

    city_urls = [
        f"https://download.db-ip.com/free/dbip-city-lite-{ym}.mmdb.gz",
        f"https://download.db-ip.com/free/dbip-city-lite-{prev_m}.mmdb.gz",
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb",
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        "https://raw.githubusercontent.com/alecthomas/geoip2/master/GeoLite2-City.mmdb",
    ]

    asn_urls = [
        f"https://download.db-ip.com/free/dbip-asn-lite-{ym}.mmdb.gz",
        f"https://download.db-ip.com/free/dbip-asn-lite-{prev_m}.mmdb.gz",
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb",
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    ]

    city_ok = _download_file(city_urls, GEOIP_DIR / "city.mmdb")
    asn_ok = _download_file(asn_urls, GEOIP_DIR / "asn.mmdb")

    if city_ok and asn_ok:
        log.info("All GeoIP binary databases downloaded successfully.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
