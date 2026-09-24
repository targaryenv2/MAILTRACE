"""Email ingestion: RFC-5322 parsing, header forensics, URL and attachment extraction."""

from .parser import (  # noqa: F401
    b64_preview, extract_urls, fingerprint, header_map, parse_auth_results,
    parse_eml, parse_received_chain, registrable, sha256_hex, strip_html,
)
