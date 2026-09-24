#!/usr/bin/env python3
# cspell: disable
"""Generate a deterministic synthetic email corpus for training and testing.

Why this exists: the public phishing corpora (Nazario, SpamAssassin, CEAS) cannot
be redistributed inside this repository, and a demo that cannot be reproduced on
a fresh clone is not a demo. ``scripts/fetch_datasets.py`` pulls the real corpora
when a machine has internet; this script guarantees that *without* internet there
is still a labelled, licence-clean, byte-identical-on-every-run corpus to train
and evaluate on.

What it is not: a benchmark. Numbers measured on synthetic mail describe the
model's ability to separate these templates, nothing more, and every artefact
this produces is stamped ``synthetic: true`` so no report can quietly imply
otherwise.

Usage:
    python scripts/make_corpus.py                 # 500 messages into data/corpus
    python scripts/make_corpus.py --count 1200
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))

SEED = 20260101

FIRST = [
    "Priya",
    "Arjun",
    "Neha",
    "Rahul",
    "Ananya",
    "Vikram",
    "Sneha",
    "Karthik",
    "Divya",
    "Rohan",
    "Meera",
    "Aditya",
    "Kavya",
    "Sanjay",
    "Ishita",
    "Nikhil",
    "James",
    "Sarah",
    "Michael",
    "Emily",
    "David",
    "Laura",
    "Daniel",
    "Anna"]
LAST = [
    "Sharma",
    "Iyer",
    "Nair",
    "Menon",
    "Reddy",
    "Kapoor",
    "Bose",
    "Rao",
    "Gupta",
    "Verma",
    "Joshi",
    "Pillai",
    "Anderson",
    "Brooks",
    "Carter",
    "Dawson",
    "Ellis",
    "Fletcher",
    "Grant",
    "Hughes"]
DEPTS = ["Finance", "Human Resources", "Engineering", "Procurement", "Legal",
         "Operations", "IT Services", "Academics", "Admissions", "Research"]

CORP_DOMAINS = [
    "northgate-industries.com",
    "vertexlogistics.in",
    "hansacapital.co",
    "meridian-labs.org",
    "kalyaniworks.in",
    "brightpath-edu.ac.in",
    "summitfoods.co.in",
    "orionsystems.io"]

BRAND_SPOOFS = [
    ("Microsoft 365", "microsoft.com", ["micros0ft-verify.com", "office365-alert.top",
                                        "microsoft-account-team.xyz", "rnicrosoft.com"]),
    ("Google Workspace", "google.com", ["google-support-desk.click",
                                        "accounts-google-verify.top", "gooogle-mail.cf"]),
    ("Apple", "apple.com", ["apple-id-locked.buzz", "appleid-verify.link", "appie.com"]),
    ("PayPal", "paypal.com", ["paypal-resolution-centre.top", "paypa1-secure.com"]),
    ("DocuSign", "docusign.com", ["docusign-review.click", "docu-sign-secure.xyz"]),
    ("State Bank of India", "sbi.co.in", ["sbi-netbanking-kyc.top", "onlinesbi-verify.click"]),
    ("HDFC Bank", "hdfcbank.com", ["hdfcbank-secure-in.xyz", "hdfc-kyc-update.link"]),
    ("Income Tax Department", "incometax.gov.in", ["incometax-refund-in.top",
                                                   "itr-refund-portal.click"]),
    ("Amazon", "amazon.in", ["amazon-order-verify.top", "arnazon.co"]),
    ("LinkedIn", "linkedin.com", ["linkedin-invitation.click", "Iinkedin-jobs.xyz"]),
]

CRED_SUBJECTS = [
    "Action required: your {brand} password expires in {hours} hours",
    "[URGENT] Unusual sign-in activity on your {brand} account",
    "Your {brand} mailbox is full - re-activate storage now",
    "{brand} security alert: verify your identity immediately",
    "Final notice: {brand} account will be suspended today",
    "Re-confirm your {brand} credentials to avoid deactivation",
]
CRED_BODY = """Dear {recipient_name},

Our records show that the password for your {brand} account ({recipient}) will
expire in {hours} hours. Failure to comply will result in a temporary suspension
of your mailbox and loss of access to shared documents.

To keep the same password and avoid interruption, verify your account here:
{link}

This is a time sensitive notice. If you do not confirm your identity within
{hours} hours the account will be deactivated automatically.

{brand} Account Services
Reference: {ref}
"""

BEC_SUBJECTS = [
    "Re: Urgent wire transfer - confidential",
    "Payment instruction (do not discuss)",
    "Quick request before end of day",
    "Change of bank details for {vendor}",
    "URGENT: release the payment today",
    "Confidential matter - need your help",
]
BEC_BODY = """{greeting} {recipient_name},

I am in back-to-back meetings so I cannot take calls. I need you to process a
wire transfer of {currency}{amount} to a new beneficiary today. This relates to
{vendor} and it is time sensitive - the deal closes end of day.

Beneficiary: {vendor}
Account: {account}
SWIFT/IBAN: {swift}

Please keep this confidential until the announcement. Do not discuss it with the
wider team. Confirm once the payment has been released.

Sent from my iPhone
{sender_name}
{title}
"""

INVOICE_SUBJECTS = [
    "Outstanding invoice {inv} - payment overdue",
    "Invoice attached: {inv} ({currency}{amount})",
    "Remittance advice {inv} - action required",
    "Purchase order {inv} needs your approval",
]
INVOICE_BODY = """Hello {recipient_name},

Please find attached invoice {inv} for {currency}{amount}, now overdue. Kindly
review the attached statement and process this payment immediately to avoid
service interruption.

If the bank details have changed since your last remittance, use the updated
account information in the attachment.

Regards,
{sender_name}
Accounts Receivable, {vendor}
"""

SCAM_SUBJECTS = [
    "Your parcel {track} could not be delivered - reschedule now",
    "Income tax refund of {currency}{amount} is pending",
    "KYC update required within 24 hours",
    "You have won a {currency}{amount} gift card - claim today",
    "Electricity connection will be disconnected tonight",
]
SCAM_BODY = """Dear customer,

{opening} Reference number: {track}.

Click here to log in and complete the process:
{link}

If we do not receive a response within 24 hours the request will be cancelled and
the amount returned to treasury.

Customer Support
{brand}
"""
SCAM_OPENINGS = [
    "Your consignment is held at our facility because the address details are incomplete.",
    "A refund has been approved against your assessment and is awaiting your bank confirmation.",
    "Your KYC documents have expired and the account has been marked for restriction.",
    "You have been selected in this month's customer appreciation draw.",
    "Payment for the current billing cycle was not received.",
]

# The hard class: grammatically clean, no urgency vocabulary, no attachment, and
# only one off-brand link. This is what an LLM-written spear phish looks like, and
# it is the case the rule engine is supposed to score mid-range with low
# confidence rather than confidently clear.
AI_SUBJECTS = [
    "Following up on the {dept} document you shared",
    "Quick question about the {vendor} agreement",
    "Notes from Tuesday and one item for review",
    "Updated {dept} template for your comments",
    "Re: the shared folder permissions",
]
AI_BODY = """Hi {recipient_name},

Thanks again for your time earlier this week. I have put the revised {dept}
document in the shared workspace and added comments against the two clauses we
discussed.

You can open it here when convenient: {link}

There is no rush on this. If the second section reads oddly, that is my drafting
rather than a change in position, so do flag it.

Best regards,
{sender_name}
{title}, {vendor}
"""

HAM_TEMPLATES = [
    ("Weekly {dept} sync - agenda", """Hi team,

Agenda for Thursday's {dept} sync:

1. Status of the {vendor} migration
2. Hiring update for the two open roles
3. Budget review before quarter close

The recording and notes will go in the usual shared folder afterwards. Add any
items to the bottom of the page before Wednesday evening.

Thanks,
{sender_name}
"""),
    ("Your order {inv} has shipped", """Hello {recipient_name},

Order {inv} shipped today and should arrive within three working days. Tracking
number {track}.

Items
- 1 x Mechanical keyboard
- 2 x USB-C cable, 1m

No action is needed. Order history is available from your account page.

{vendor} Customer Care
"""),
    ("Payslip for {month} is available", """Dear {recipient_name},

Your payslip for {month} is now available on the employee portal. Log in through
the usual internal link on the intranet home page.

If any of the tax details look incorrect, raise a ticket with Payroll and we will
correct it in the next cycle.

Regards,
Payroll Team
{vendor}
"""),
    ("PR #{num}: refactor the retry handler", """{sender_name} requested your review on pull request #{num}.

  refactor: collapse the three retry paths into one backoff helper

Changed 6 files, +148 -211. CI is green. The behaviour change worth checking is
that a 429 now retries twice instead of once.

View it in the repository when you get a chance.
"""),
    ("Maintenance window: Saturday 02:00-04:00 IST", """Hello,

Planned maintenance on the {dept} systems this Saturday between 02:00 and 04:00
IST. Expect a short interruption while the database fails over.

No user action is required. We will send a note here once the window closes.

{dept} Operations
"""),
    ("Reminder: submit {dept} timesheets by Friday", """Hi {recipient_name},

A reminder that {month} timesheets close on Friday. If you are on leave, your
approver can submit on your behalf.

Thanks,
{sender_name}
{dept}
"""),
    ("Conference paper decision - {vendor} workshop", """Dear {recipient_name},

Thank you for your submission to the {vendor} workshop. The reviewers have
recommended acceptance with minor revisions. Reviews are attached to the
submission record in the conference system.

Camera-ready copies are due at the end of the month.

Programme Committee
"""),
    ("Welcome to the team, {recipient_name}", """Hi {recipient_name},

Welcome aboard. Your laptop is at the IT desk on the second floor and your
manager will walk you through the first-week plan tomorrow morning.

Lunch is on us on Friday.

{sender_name}
Human Resources, {vendor}
"""),
    ("Invoice {inv} paid", """Hello,

This confirms that invoice {inv} for {currency}{amount} was paid on {date_short}
by bank transfer to the account already on file. No further action is needed.

Accounts Payable
{vendor}
"""),
    ("Library books due {month}", """Dear {recipient_name},

Two items on your library account are due at the end of {month}. Renewals can be
made at the circulation desk or from the catalogue page.

Central Library
"""),
]

MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]

RELAY_POOL = [
    # (ip, hostname, country hint) - documentation and TEST-NET ranges only, so
    # nothing here can ever resolve to a real third party's infrastructure.
    ("192.0.2.10", "mx1.mail-relay.example", "sg"),
    ("192.0.2.44", "smtp-out-3.example", "us"),
    ("198.51.100.7", "vps-31.hosting.example", "nl"),
    ("198.51.100.89", "relay.open-smtp.example", "ru"),
    ("203.0.113.5", "mail.gateway.example", "in"),
    ("203.0.113.61", "edge-2.mailcluster.example", "de"),
    ("192.0.2.201", "tor-exit-node.example", "ro"),
    ("198.51.100.150", "compute-04.cloudprovider.example", "us"),
]

PDF_MAGIC = b"%PDF-1.4\n%stub\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n"
ZIP_MAGIC = b"PK\x03\x04" + b"\x00" * 26 + b"payload-stub"
DOC_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40 + b"VBA-macro-stub"
EXE_MAGIC = b"MZ\x90\x00\x03" + b"\x00" * 50 + \
    b"This program cannot be run in DOS mode"


def _person(rng: random.Random) -> tuple[str, str]:
    return rng.choice(FIRST), rng.choice(LAST)


def _addr(first: str, last: str, domain: str) -> str:
    return f"{first.lower()}.{last.lower()}@{domain}"


def _html(body: str, link: str = "", anchor: str = "") -> str:
    paras = "".join("<p>{}</p>".format(p.replace("\n", " ").strip())
                    for p in body.split("\n\n") if p.strip())
    if link:
        paras += f'<p><a href="{link}">{anchor or link}</a></p>'
    return ("<html><body style=\"font-family:Segoe UI,Arial,sans-serif;"
            f"font-size:14px;color:#202124\">{paras}</body></html>")


def _received(rng: random.Random, dest_domain: str, base: datetime,
              hops: int, include_anomaly: bool) -> list[str]:
    """Build a Received chain, newest first.

    Newest-first is the order a real MTA leaves behind: every server *prepends*
    its own header, so the topmost header is the last hop and the bottom-most is
    the originating node. Two things have to hold for the chain to be coherent,
    and an earlier version of this function got both wrong:

    * ``by`` must name the host that received the message from ``from`` - i.e. the
      next hop along the path, with the final header handing off to the
      recipient's MX. Naming one fixed host in every header is a tell.
    * timestamps must **ascend** from the bottom of the file to the top. When they
      ran the other way, the analyser's earliest-reliable-hop logic correctly
      identified the recipient's own gateway as the origin, which made every trace
      point at the victim.

    The anonymising hop, when one is requested, is placed at the *origin*, because
    that is where it actually changes the investigation: it is the point past
    which the header trail cannot go. When one is *not* requested the anonymising
    relays are removed from the pool entirely. Leaving them in meant roughly a
    third of the legitimate messages arrived via a Tor exit or an open relay,
    which is label noise, not realism: the analyser correctly flagged a relay
    anomaly on mail labelled benign, and the model was being taught that Tor
    exits are normal.
    """
    anonymising = ("tor", "open-smtp")
    pool = [hop for hop in RELAY_POOL
            if include_anomaly or not any(a in hop[1] for a in anonymising)]
    rng.shuffle(pool)
    # ``hops`` means hops. An earlier ``hops - 1`` here silently produced
    # single-header chains for the most common draw, which left nothing to trace
    # and no transit path to draw on the map.
    path = pool[:max(2, min(hops, len(pool)))]  # earliest -> latest
    if include_anomaly:
        anon = [i for i, (_ip, host, _cc) in enumerate(path)
                if any(a in host for a in anonymising)]
        if anon:
            path.insert(0, path.pop(anon[0]))  # move it to the origin
        else:
            path[0] = ("192.0.2.201", "tor-exit-node.example", "ro")

    # Per-hop transit delays, then absolute times ending at ``base`` for the last
    # hop, so the whole chain sits before the Date header rather than after it.
    gaps = [rng.randint(2, 400) for _ in path]
    stamps: list[datetime] = []
    t = base - timedelta(seconds=sum(gaps))
    for gap in gaps:
        t = t + timedelta(seconds=gap)
        stamps.append(t)

    chain: list[str] = []
    for i in range(len(path) - 1, -1, -1):  # newest first
        ip, host, _cc = path[i]
        if i + 1 < len(path):
            by, tail = path[i + 1][1], ""
        else:
            by = f"mx.{dest_domain}"
            tail = f" for <recipient@{dest_domain}>"
        chain.append(
            "from {} ({} [{}]) by {} (Postfix) with ESMTPS id {}{}; {}".format(host, host, ip, by, f"{rng.getrandbits(48):012X}", tail,
               format_datetime(stamps[i]))
        )
    return chain


def _auth_headers(
        msg: EmailMessage,
        rng: random.Random,
        from_domain: str,
        envelope_domain: str,
        spf: str,
        dkim: str,
        dmarc: str) -> None:
    msg["Received-SPF"] = f"{spf} (mailfrom) identity=mailfrom; client-ip={rng.choice(RELAY_POOL)[0]}; envelope-from=<bounce@{envelope_domain}>;"
    msg["Authentication-Results"] = (
        "mx.{}; spf={} smtp.mailfrom={}; dkim={} header.d={}; dmarc={} (p={}) header.from={}".format(from_domain,
         spf,
         envelope_domain,
         dkim,
         from_domain if dkim == "pass" else envelope_domain,
         dmarc,
         "reject" if dmarc != "none" else "none",
         from_domain))
    if dkim != "none":
        msg["DKIM-Signature"] = (
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=selector1; t=%d; "
            "h=from:to:subject:date; bh=%s; b=%s" %
            (from_domain if dkim == "pass" else envelope_domain, int(
                rng.random() * 1e9), base64.b64encode(
                bytes(
                    rng.getrandbits(8) for _ in range(32))).decode(), base64.b64encode(
                    bytes(
                        rng.getrandbits(8) for _ in range(64))).decode()))


def _finish(msg: EmailMessage, rng: random.Random, text: str, html: str,
            attachment: tuple[str, str, bytes] | None = None) -> bytes:
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if attachment:
        name, mime, data = attachment
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(
            data,
            maintype=maintype,
            subtype=subtype,
            filename=name)
    return msg.as_bytes()


def make_phish(rng: random.Random, kind: str,
               base_time: datetime) -> tuple[bytes, dict]:
    brand, real_domain, spoofs = rng.choice(BRAND_SPOOFS)
    spoof = rng.choice(spoofs)
    rf, rl = _person(rng)
    corp = rng.choice(CORP_DOMAINS)
    recipient = _addr(rf, rl, corp)
    sf, sl = _person(rng)
    vendor = rng.choice(["Kestrel Supplies Ltd",
                         "Aurora Freight",
                         "Bluestone Partners",
                         "Trident Components",
                         "Lakeside Consulting",
                         "Zenith Traders"])
    ref = "%s-%05d" % (rng.choice(["MS", "SEC",
                       "ACC", "TX"]), rng.randint(1, 99999))
    hours = rng.choice([12, 24, 48, 6])
    amount = f"{rng.randrange(45_000, 9_500_000, 1000):,}"
    currency = rng.choice(["$", "INR ", "EUR "])
    inv = "INV-%d-%04d" % (rng.choice([2025, 2026]), rng.randint(100, 9999))
    track = "%s%09d" % (rng.choice(
        ["AWB", "TRK", "CN"]), rng.randint(1, 999999999))
    dept = rng.choice(DEPTS)
    link = "https://{}/{}".format(spoof,
                              rng.choice(["login",
                                          "account/verify",
                                          "secure/signin",
                                          "session/renew",
                                          "auth/confirm"]))
    msg = EmailMessage()
    attachment = None
    tags: list[str] = [kind]

    if kind == "credential":
        subject = rng.choice(CRED_SUBJECTS).format(brand=brand, hours=hours)
        text = CRED_BODY.format(
            recipient_name=rf,
            brand=brand,
            recipient=recipient,
            hours=hours,
            link=link,
            ref=ref)
        # Display name carries the brand while the domain does not: the classic
        # display-name spoof.
        msg["From"] = '"{} Security" <{}>'.format(brand, "no-reply@" + spoof)
        from_domain = spoof
        env = spoof
        spf, dkim, dmarc = rng.choice([("fail", "none", "fail"), ("pass", "fail", "fail"),
                                       ("softfail", "none", "fail")])
        html = _html(text, link, "Verify my account")
        tags += ["credential-harvest", "display-name-spoof"]
    elif kind == "bec":
        subject = rng.choice(BEC_SUBJECTS).format(vendor=vendor)
        text = BEC_BODY.format(greeting=rng.choice(["Hi", "Hello", "Dear"]),
                               recipient_name=rf, currency=currency, amount=amount,
                               vendor=vendor, account="%d" % rng.randrange(10**10, 10**11),
                               swift=rng.choice(["HSBCGB2L", "DEUTDEFF", "SBININBB104"]),
                               sender_name=f"{sf} {sl}",
                               title=rng.choice(["Chief Executive Officer", "Managing Director",
                                                 "CFO", "Chairman"]))
        free = rng.choice(["gmail.com", "outlook.com", "yahoo.com"])
        msg["From"] = f'"{sf} {sl} (CEO)" <{_addr(sf, sl, free)}>'
        msg["Reply-To"] = f"{sf.lower()}.{sl.lower()}.office@{free}"
        from_domain = free
        env = free
        spf, dkim, dmarc = "pass", "pass", "pass"  # freemail really does authenticate
        html = ""  # text-only, no payload: nothing for a link scanner to find
        tags += ["bec", "payment-diversion", "freemail-executive"]
    elif kind == "invoice":
        subject = rng.choice(INVOICE_SUBJECTS).format(
            inv=inv, currency=currency, amount=amount)
        text = INVOICE_BODY.format(
            recipient_name=rf,
            inv=inv,
            currency=currency,
            amount=amount,
            sender_name=f"{sf} {sl}",
            vendor=vendor)
        msg["From"] = '"{} Accounts" <{}>'.format(vendor, "billing@" + spoof)
        from_domain = spoof
        env = spoof
        spf, dkim, dmarc = rng.choice(
            [("fail", "none", "fail"), ("softfail", "fail", "fail")])
        html = _html(text)
        pick = rng.random()
        if pick < 0.35:
            attachment = (
                f"{inv}.pdf.exe",
                "application/octet-stream",
                EXE_MAGIC)
            tags.append("double-extension")
        elif pick < 0.6:
            attachment = (f"{inv}.doc", "application/msword", DOC_MAGIC)
            tags.append("macro-document")
        elif pick < 0.8:
            attachment = (f"{inv}.zip", "application/zip", ZIP_MAGIC)
            tags.append("archive")
        else:
            # A .pdf whose bytes are a PE binary: extension/magic mismatch.
            attachment = (
                f"statement_{inv}.pdf", "application/pdf", EXE_MAGIC)
            tags.append("type-mismatch")
        tags.append("malicious-attachment")
    elif kind == "scam":
        subject = rng.choice(SCAM_SUBJECTS).format(
            track=track, currency=currency, amount=amount)
        text = SCAM_BODY.format(opening=rng.choice(SCAM_OPENINGS), track=track,
                                link=link, brand=brand)
        msg["From"] = '"{}" <{}>'.format(brand, "notice@" + spoof)
        from_domain = spoof
        env = spoof
        spf, dkim, dmarc = "fail", "none", "fail"
        # Mismatched anchor text: the reader sees the real brand domain.
        html = _html(text, link, f"https://www.{real_domain}/verify")
        tags += ["consumer-scam", "anchor-mismatch"]
        if rng.random() < 0.3:
            link = "http://{}/{}".format(rng.choice(
                ["198.51.100.77", "203.0.113.99"]), "login")
            html = _html(text, link, f"https://www.{real_domain}/verify")
            tags.append("ip-literal-link")
    else:  # ai_generated
        subject = rng.choice(AI_SUBJECTS).format(dept=dept, vendor=vendor)
        # A plausible-looking file-share host, not a keyword-stuffed domain.
        link = "https://{}/d/{}".format(rng.choice(["docs-workspace.app",
                                                "sharedrive-review.io",
                                                "teamfiles-hub.co"]),
                                    f"{rng.getrandbits(32):08x}")
        text = AI_BODY.format(recipient_name=rf, dept=dept, link=link,
                              sender_name=f"{sf} {sl}",
                              title=rng.choice(["Partner", "Programme Manager",
                                                "Associate Director"]), vendor=vendor)
        look = rng.choice(CORP_DOMAINS)
        msg["From"] = f'"{sf} {sl}" <{_addr(sf, sl, look)}>'
        from_domain = look
        env = look
        spf, dkim, dmarc = "pass", "pass", "pass"
        html = _html(text, link, "shared workspace")
        tags += ["ai-generated-style", "low-signal", "hard-negative"]

    msg["To"] = f"{rf} {rl} <{recipient}>"
    msg["Subject"] = subject
    sent = base_time - timedelta(minutes=rng.randint(1, 60 * 24 * 30))
    msg["Date"] = format_datetime(sent)
    msg["Message-ID"] = make_msgid(domain=from_domain)
    msg["Return-Path"] = "<bounce-%d@%s>" % (rng.randint(1000, 9999), env)
    msg["MIME-Version"] = "1.0"
    if rng.random() < 0.35:
        msg["X-Mailer"] = rng.choice(["PHPMailer 6.1.6",
                                     "smtplib/3.9", "BulkSend 2.1"])
    for h in _received(rng, corp, sent, rng.randint(2, 5),
                       include_anomaly=rng.random() < 0.4):
        msg["Received"] = h
    _auth_headers(msg, rng, from_domain, env, spf, dkim, dmarc)
    raw = _finish(msg, rng, text, html, attachment)
    return raw, {"label": 1, "kind": kind, "tags": sorted(set(tags)),
                 "subject": subject, "from_domain": from_domain,
                 "spf": spf, "dkim": dkim, "dmarc": dmarc}


def make_ham(rng: random.Random, base_time: datetime) -> tuple[bytes, dict]:
    subj_t, body_t = rng.choice(HAM_TEMPLATES)
    rf, rl = _person(rng)
    sf, sl = _person(rng)
    corp = rng.choice(CORP_DOMAINS)
    vendor = rng.choice(["Northgate Industries",
                         "Vertex Logistics",
                         "Meridian Labs",
                         "Brightpath Institute",
                         "Summit Foods",
                         "Orion Systems"])
    fields = {
        "dept": rng.choice(DEPTS), "vendor": vendor, "recipient_name": rf,
        "sender_name": f"{sf} {sl}",
        "inv": "INV-%d-%04d" % (rng.choice([2025, 2026]), rng.randint(100, 9999)),
        "track": "%s%09d" % (rng.choice(["AWB", "TRK"]), rng.randint(1, 999999999)),
        "month": rng.choice(MONTHS), "num": rng.randint(100, 4000),
        "amount": f"{rng.randrange(1200, 480000, 100):,}",
        "currency": rng.choice(["$", "INR "]),
        "date_short": (base_time - timedelta(days=rng.randint(1, 40))).strftime("%d %b %Y"),
    }
    subject = subj_t.format(**fields)
    text = body_t.format(**fields)
    msg = EmailMessage()
    msg["From"] = f'"{sf} {sl}" <{_addr(sf, sl, corp)}>'
    msg["To"] = f"{rf} {rl} <{_addr(rf, rl, corp)}>"
    msg["Subject"] = subject
    sent = base_time - timedelta(minutes=rng.randint(1, 60 * 24 * 30))
    msg["Date"] = format_datetime(sent)
    msg["Message-ID"] = make_msgid(domain=corp)
    msg["Return-Path"] = f"<{_addr(sf, sl, corp)}>"
    msg["MIME-Version"] = "1.0"
    for h in _received(
            rng,
            corp,
            sent,
            rng.randint(
                2,
                3),
            include_anomaly=False):
        msg["Received"] = h
    _auth_headers(msg, rng, corp, corp, "pass", "pass", "pass")
    html = _html(text) if rng.random() < 0.6 else ""
    attachment = None
    if rng.random() < 0.25:
        attachment = ("{}.pdf".format(fields["inv"]), "application/pdf", PDF_MAGIC)
    raw = _finish(msg, rng, text, html, attachment)
    return raw, {"label": 0, "kind": "ham", "tags": ["legitimate"], "subject": subject,
                 "from_domain": corp, "spf": "pass", "dkim": "pass", "dmarc": "pass"}


MALFORMED = [
    (b"Subject: no headers at all just a body\r\n\r\nThis file is missing From, "
     b"Date, Message-ID and every Received header.\r\n",
     {"label": 1, "kind": "malformed", "tags": ["malformed", "missing-headers"],
      "subject": "no headers at all just a body", "from_domain": ""}),
    (b"From: broken <@@@>\r\nTo: someone\r\nSubject: =?utf-8?B?bm90LXZhbGlkLWJhc2U2NA?"
     b"\r\nContent-Type: multipart/mixed; boundary=\"missing\"\r\n\r\n"
     b"--missing\r\nContent-Type: text/plain\r\n\r\ntruncated body with no closing "
     b"boundary and a broken encoded-word subject\r\n",
     {"label": 1, "kind": "malformed", "tags": ["malformed", "broken-mime", "bad-address"],
      "subject": "", "from_domain": ""}),
]


def _prune_stale(directories: list[Path], written: set) -> list[str]:
    """Remove ``.eml`` files left behind by an earlier run.

    File names are index-based, and the index of a given template shifts whenever
    the mixture or the seed changes, so a re-run leaves orphans behind. Orphans
    are not harmless: a message generated as phishing under the old mixture can
    survive in ``ham/`` under the new one, and anything that globs the directory
    instead of reading the manifest then trains on a mislabelled example. This is
    exactly how a "legitimate" message that arrived via a Tor exit ended up in
    the corpus.

    Returns the paths it could not remove, so the caller can say so out loud
    rather than leaving a silent inconsistency. On a locked-down filesystem the
    manifest remains the authority: every consumer in this repository reads it.
    """
    stale: list[str] = []
    for directory in directories:
        for path in sorted(directory.glob("*.eml")):
            if str(path.resolve()) in written:
                continue
            try:
                path.unlink()
            except OSError:
                stale.append(str(path))
    return stale


def generate(count: int, out_dir: Path) -> dict:
    rng = random.Random(SEED)
    base_time = datetime(2026, 6, 1, 9, 30, tzinfo=timezone.utc)
    phish_dir = out_dir / "phishing"
    ham_dir = out_dir / "ham"
    for d in (phish_dir, ham_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Mixture chosen so every rule family and the hard low-signal class are all
    # represented, and so ham stays close to half the corpus.
    mix = [("credential", 0.16), ("bec", 0.11), ("invoice", 0.11),
           ("scam", 0.10), ("ai_generated", 0.06)]
    n_phish_each = {k: max(2, int(count * w)) for k, w in mix}
    n_phish = sum(n_phish_each.values())
    n_ham = max(2, count - n_phish - len(MALFORMED))

    records: list[dict] = []
    seen: dict[str, str] = {}
    written: set = set()

    def emit(raw: bytes, meta: dict, directory: Path, idx: int) -> None:
        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:  # identical template fill: skip so no duplicate leaks
            return          # across the train/test split
        name = "%s-%04d.eml" % (meta["kind"], idx)
        path = directory / name
        path.write_bytes(raw)
        written.add(str(path.resolve()))
        seen[digest] = name
        meta = dict(meta)
        meta.update({"file": str(path.relative_to(out_dir)).replace("\\", "/"),
                     "sha256": digest, "size_bytes": len(raw)})
        records.append(meta)

    idx = 0
    for kind, n in sorted(n_phish_each.items()):
        for _ in range(n):
            idx += 1
            raw, meta = make_phish(rng, kind, base_time)
            emit(raw, meta, phish_dir, idx)
    for _ in range(n_ham):
        idx += 1
        raw, meta = make_ham(rng, base_time)
        emit(raw, meta, ham_dir, idx)
    for i, (raw, meta) in enumerate(MALFORMED, 1):
        emit(raw, meta, phish_dir, 9000 + i)

    stale = _prune_stale([phish_dir, ham_dir], written)

    manifest = out_dir / "manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as fh:
        for r in sorted(records, key=lambda r: r["file"]):
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": SEED,
        "synthetic": True,
        "total": len(records),
        "phishing": sum(1 for r in records if r["label"] == 1),
        "ham": sum(1 for r in records if r["label"] == 0),
        "by_kind": {k: sum(1 for r in records if r["kind"] == k)
                    for k in sorted({r["kind"] for r in records})},
        "licence": "Generated by scripts/make_corpus.py. No third-party content, "
                   "safe to redistribute. All IPs are from RFC 5737 documentation "
                   "ranges and all domains use reserved or invented names.",
        "stale_files_not_removed": stale,
        "warning": "Synthetic corpus. Metrics measured on it describe separability "
                   "of these templates only and are not a benchmark result.",
    }
    (out_dir / "corpus_info.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate the synthetic MailTrace corpus")
    ap.add_argument("--count", type=int, default=500,
                    help="approximate total messages")
    ap.add_argument("--out", default=str(REPO / "data" / "corpus"))
    args = ap.parse_args()
    summary = generate(args.count, Path(args.out))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
