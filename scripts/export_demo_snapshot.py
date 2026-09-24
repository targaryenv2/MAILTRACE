#!/usr/bin/env python3
"""Export a frozen API snapshot for the frontend's offline mode.

The console needs to work when there is no backend: a judge opening the built
``dist/`` from a file server, a laptop with the Python side not started, a
GitHub Pages demo. The obvious way to do that is to hand-write fixtures in
TypeScript, and the obvious problem with that is drift - hand-written fixtures
stop matching the API the first time a field is renamed, and the demo starts
lying about what the system produces.

So this script seeds the real database, calls the real routing table in-process
(no HTTP, no port, nothing to leave running) and writes whatever the API
actually returned to ``frontend/src/lib/demoSnapshot.json``. The snapshot is
generated output, not authored content: if the API changes shape, regenerate.

Usage::

    python scripts/export_demo_snapshot.py            # seed if empty, then export
    python scripts/export_demo_snapshot.py --reseed   # force a fresh seed
    python scripts/export_demo_snapshot.py --cases 8  # cap the bundled cases

Masking is forced on. This file ends up in a public repository and in a
JavaScript bundle, so every recipient identity in it must already be destroyed
before it is written - not masked at render time by the code that reads it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.api.routes import Request, dispatch  # noqa: E402
from app.config import get_settings  # noqa: E402

OUT = REPO / "frontend" / "src" / "lib" / "demoSnapshot.json"


def call(path: str, method: str = "GET", **query: Any) -> Any:
    """Invoke one endpoint and return its decoded JSON payload."""
    q = {k: str(v) for k, v in query.items() if v is not None}
    resp = dispatch(Request(method=method, path=path, query=q))
    body = resp.body.decode("utf-8", "replace")
    if resp.status >= 400:
        raise SystemExit("%s %s -> %s %s" %
                         (method, path, resp.status, body[:200]))
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise SystemExit(
            "%s %s returned non-JSON (%s)" %
            (method, path, resp.content_type))


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--reseed",
        action="store_true",
        help="seed even if cases exist")
    ap.add_argument(
        "--cases",
        type=int,
        default=12,
        help="max cases to bundle")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)

    st = get_settings()
    st.ensure_dirs()
    # Force masking regardless of the developer's .env: this output is public.
    was_masking = st.pii_masking
    st.pii_masking = True
    try:
        existing = call("/api/stats").get("total", 0)
        if args.reseed or not existing:
            print("seeding demo corpus...")
            seeded = call("/api/ingest/demo", "POST", wave="true")
            print("  seeded %s cases" % seeded.get("count", "?"))

        health = call("/api/health")
        queue = call("/api/cases", limit=args.cases, sort="risk")
        summaries = queue.get("items", [])
        if not summaries:
            raise SystemExit("no cases to export; run with --reseed")

        cases: Dict[str, Any] = {}
        maps: Dict[str, Any] = {}
        graphs: Dict[str, Any] = {}
        audits: Dict[str, Any] = {}
        takedowns: Dict[str, Any] = {}
        chains: Dict[str, Any] = {}
        for row in summaries:
            ref = row["case_number"]
            print("  exporting %s" % ref)
            cases[ref] = call("/api/cases/%s" % ref, mask="true")
            maps[ref] = call("/api/cases/%s/map" % ref)
            graphs[ref] = call("/api/cases/%s/graph" % ref, scan=200)
            audits[ref] = call("/api/cases/%s/audit" % ref, limit=60)
            takedowns[ref] = call("/api/cases/%s/takedown" % ref)
            chains[ref] = call("/api/chain/%s" % ref)

        snapshot = {
            "_generated_by": "scripts/export_demo_snapshot.py",
            "_note": (
                "Frozen API responses used when the backend is unreachable. "
                "Generated from a real pipeline run with PII masking forced on. "
                "Regenerate after any API shape change; do not hand-edit."),
            "generated_at": health.get("time"),
            "health": health,
            "stats": call("/api/stats"),
            "config": call("/api/config"),
            "model": call("/api/model"),
            "privacy": call("/api/privacy"),
            "retention": call("/api/privacy/retention"),
            "campaigns": call(
                "/api/campaigns",
                limit=25),
            "queue": queue,
            "cases": cases,
            "maps": maps,
            "graphs": graphs,
            "audits": audits,
            "takedowns": takedowns,
            "chains": chains,
        }
    finally:
        st.pii_masking = was_masking

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys and a trailing newline so regeneration produces a reviewable
    # diff instead of a reordered blob.
    out.write_text(
        json.dumps(
            snapshot,
            indent=1,
            sort_keys=True) +
        "\n",
        encoding="utf-8")
    kb = out.stat().st_size / 1024
    print("wrote %s (%.0f KB, %d cases)" % (out, kb, len(cases)))
    if kb > 900:
        print("  note: this ships inside the JS bundle; consider --cases 8 if it grows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
