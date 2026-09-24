"""Generate one phishing *wave*: the same lure sent to several people at one org.

Why this exists as its own script. ``make_corpus.py`` randomises every field of
every message, which is right for training data - it stops the model latching
onto a single template - but it means no two generated messages ever share a
campaign fingerprint. The result was a working campaign-correlation feature with
nothing to correlate: seven demo cases, seven "campaigns" of one case each.

A real campaign is the opposite shape. One actor, one lure, one landing page,
many recipients inside a single organisation, arriving minutes apart. That is
what ``fingerprint()`` is designed to collapse (it excludes recipient and
Message-ID on purpose), and it is what the blast-radius and campaign roll-up
screens exist to show. So this script takes one generated message and re-addresses
it, the way the sending script behind a real wave would.

Output goes to ``data/demo/wave/`` and is ingested by ``seed_demo()`` alongside
the seven hand-built demo emails.

With ``--update-directory`` it also writes the matching exposure entry into
``data/fixtures/org_directory.json``, keyed on the fingerprint it just computed,
so blast radius reports click-through for this wave instead of "unavailable".
Every person in that fixture is invented; see the note in the file itself.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from datetime import datetime, timezone
from email import message_from_bytes
from email.policy import default as default_policy
from pathlib import Path
from typing import Dict, List, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "backend"))

from make_corpus import CORP_DOMAINS, SEED, _addr, _person, make_phish  # noqa: E402

# Realistic wave shape: a finance-heavy target list, and engagement that decays
# down the list the way real click-through does.
ENGAGEMENT: List[Tuple[str, str, Dict[str, bool]]] = [
    ("Accounts Payable Officer", "Finance",
     {"delivered": True, "opened": True, "clicked": True, "submitted_credentials": True}),
    ("Finance Manager", "Finance",
     {"delivered": True, "opened": True, "clicked": True}),
    ("Payroll Administrator", "Finance",
     {"delivered": True, "opened": True}),
    ("Procurement Lead", "Operations",
     {"delivered": True, "opened": True, "reported": True}),
    ("Security Analyst", "Information Security",
     {"delivered": True, "opened": True, "reported": True}),
    ("Regional Sales Manager", "Sales",
     {"delivered": True}),
]


def _rewrite(
        raw: bytes,
        old_to: str,
        old_name: str,
        new_to: str,
        new_name: str,
        seq: int,
        base: datetime) -> bytes:
    """Re-address one copy of the wave.

    Only the recipient changes: To, the ``for <...>`` clause the receiving MTA
    stamps into the final Received header, the in-body salutation, and the
    Message-ID (which must be unique per message or the store dedupes them as
    the same evidence). Subject, From, links, attachments and the upstream relay
    chain are held constant - that constancy is the campaign.
    """
    msg = message_from_bytes(raw, policy=default_policy)
    del msg["To"]
    msg["To"] = new_to
    mid = "<wave-%s-%03d@%s>" % (base.strftime("%Y%m%d%H%M"), seq,
                                 old_to.rpartition("@")[2] or "localhost")
    del msg["Message-ID"]
    msg["Message-ID"] = mid
    out = msg.as_bytes()
    # Body/Received substitutions are byte-level on purpose: the payload is 7-bit
    # ASCII here, so this cannot corrupt an encoded part, and going through the
    # payload API would re-encode parts that are currently byte-identical across
    # the wave (which is evidence we want preserved).
    out = out.replace(old_to.encode(), new_to.encode())
    if old_name:
        out = out.replace(old_name.encode(), new_name.encode())
    return out


def generate(kind: str, count: int, out_dir: Path) -> Dict[str, object]:
    rng = random.Random(SEED + 7717)
    base = datetime(2026, 6, 2, 7, 15, tzinfo=timezone.utc)
    raw, _meta = make_phish(rng, kind, base)

    hdr = message_from_bytes(raw, policy=default_policy)
    old_to = str(hdr.get("To", ""))
    old_addr = re.search(r"[\w.+-]+@[\w.-]+", old_to)
    old_addr = old_addr.group(0) if old_addr else ""
    old_first = old_addr.split(".")[0].capitalize() if old_addr else ""
    corp = old_addr.rpartition("@")[2] or rng.choice(CORP_DOMAINS)

    out_dir.mkdir(parents=True, exist_ok=True)
    people: List[Dict[str, object]] = []
    files: List[str] = []
    n = min(count, len(ENGAGEMENT))
    for i in range(n):
        first, last = _person(rng)
        addr = _addr(first, last, corp)
        if addr == old_addr:  # vanishingly unlikely, but a collision would
            last = last + "s"  # silently shrink the wave by one
            addr = _addr(first, last, corp)
        role, dept, events = ENGAGEMENT[i]
        body = _rewrite(raw, old_addr, old_first, addr, first, i + 1, base)
        name = "wave-%s-%02d.eml" % (kind, i + 1)
        (out_dir / name).write_bytes(body)
        files.append(name)
        person: Dict[str, object] = {
            "email": addr, "name": "%s %s" % (first, last), "role": role,
            "department": dept,
            "last_event_at": base.replace(minute=15 + i * 3).isoformat(),
        }
        person.update(events)
        people.append(person)

    fp = ""
    try:  # fingerprint needs the backend; a missing backend is not fatal here
        from app.ingestion.parser import fingerprint, parse_eml  # noqa: PLC0415

        fp = fingerprint(
            parse_eml(
                (out_dir / files[0]).read_bytes(),
                files[0]))
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed silently
        print(
            "warning: could not compute fingerprint (%s)" %
            exc, file=sys.stderr)

    index = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": SEED + 7717,
        "synthetic": True,
        "kind": kind,
        "fingerprint": fp,
        "sender": str(hdr.get("From", "")).strip(),
        "subject": str(hdr.get("Subject", "")).strip(),
        "target_domain": corp,
        "files": files,
        "recipients": [p["email"] for p in people],
        "note": "One campaign, %d recipients at one organisation. Exists so the "
                "campaign roll-up and blast-radius screens have a real wave to "
                "show. Same generator and same reserved address ranges as the "
                "rest of the corpus." % len(people),
    }
    (out_dir / "wave_index.json").write_text(
        json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return {"index": index, "people": people}


def update_directory(
        fp: str, people: List[Dict[str, object]], subject: str) -> None:
    """Add this wave's exposure record to the org-directory fixture."""
    path = REPO / "data" / "fixtures" / "org_directory.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(
            "warning: org_directory.json unreadable (%s)" %
            exc, file=sys.stderr)
        return
    if not fp:
        print("warning: no fingerprint, directory not updated", file=sys.stderr)
        return
    staff = doc.setdefault("staff", [])
    known = {str(s.get("email", "")).lower() for s in staff}
    for p in people:
        email = str(p["email"])
        if email.lower() not in known:
            staff.append({"email": email, "name": p.get("name", ""),
                          "role": p.get("role", ""),
                          "department": p.get("department", "")})
            known.add(email.lower())
    doc.setdefault(
        "waves",
        {})[fp] = {
        "label": "generated wave: %s" %
        subject,
        "source": "synthetic wave produced by scripts/make_wave.py; stands in for a "
        "mail-gateway delivery report",
        "recipients": people,
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("org_directory.json: wave %s -> %d recipients" %
          (fp[:12], len(people)))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate one phishing campaign wave")
    ap.add_argument(
        "--kind",
        default="credential",
        choices=[
            "credential",
            "bec",
            "invoice",
            "scam",
            "ai_generated"])
    ap.add_argument(
        "--count",
        type=int,
        default=6,
        help="recipients in the wave")
    ap.add_argument("--out", default=str(REPO / "data" / "demo" / "wave"))
    ap.add_argument(
        "--update-directory",
        action="store_true",
        help="write the matching exposure entry into org_directory.json")
    args = ap.parse_args()
    result = generate(args.kind, args.count, Path(args.out))
    index = result["index"]
    if args.update_directory:
        update_directory(str(index["fingerprint"]), result["people"],
                         str(index["subject"]))
    print(json.dumps(index, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
