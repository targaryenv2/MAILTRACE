# MailTrace — Automated Email Threat Intelligence Platform

**SIH 2026 | Team Targaryen**

MailTrace is a full-stack email security operations platform. It parses raw emails, validates authentication records, runs a 5-class ML classifier, traces infrastructure through GeoIP and threat intel APIs, maps findings to MITRE ATT&CK, maintains a verifiable blockchain-anchored evidence chain, and delivers results through a React dashboard and a Chrome extension that banners Gmail and Zoho Mail in real time.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [ML Model](#ml-model)
- [Detection Pipeline](#detection-pipeline)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup & Running](#setup--running)
- [Chrome Extension](#chrome-extension)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)

---

## Architecture Overview

```
Raw Email (.eml / paste)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│                   Ingestion & Parsing                   │
│  • Header decode  • Auth extraction (SPF/DKIM/DMARC)   │
│  • URL extraction • Attachment inspection               │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Agentic Investigation Loop                 │
│                                                         │
│  L1 header_and_content_analysis  (rules + NLP)         │
│  L2 relay_path_reconstruction    (GeoIP + hops)        │
│  L3 ml_classification            (TF-IDF + LR)         │
│  L4 threat_intel_enrichment      (AbuseIPDB/VT/WHOIS)  │
│  L5 link_detonation              (Playwright sandbox)  │
│                                                         │
│  → early-exit when conclusive, quota-aware             │
└──────────────────────────┬──────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        Verdict +    MITRE ATT&CK   Campaign
        SHAP explain  mapping      clustering
              │
              ▼
        Neo4j Graph DB
    (Case, IOC, Signal, Sender,
     Domain, IP, UrlHost, Attachment)
              │
              ▼
    Blockchain custody receipt
    (Keccak-256 hash on-chain)
              │
              ▼
    React Dashboard + Chrome Extension
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | Python 3.11, stdlib `ThreadingHTTPServer` |
| ML / NLP | scikit-learn, TF-IDF, Logistic Regression, SHAP |
| Database | **Neo4j 5.x** (graph) |
| GeoIP | MaxMind GeoLite2 (City + ASN) |
| Threat Intel | AbuseIPDB, VirusTotal, DNSBL |
| Blockchain | Web3 / Keccak-256, simulated or live EVM chain |
| Frontend | React 18, Vite, TypeScript |
| Chrome Extension | Manifest V3, content scripts for Gmail + Zoho Mail |
| PDF Reports | ReportLab |

---

## ML Model

### Architecture

```
TfidfVectorizer(ngram_range=(1,3), max_features=50,000, sublinear_tf=True)
        +
CalibratedClassifierCV(
    LogisticRegression(multinomial, class_weight=balanced, solver=lbfgs),
    method="isotonic", cv=3
)
```

Serialised to `ml/models/phish_tfidf_lr_real.joblib`.

### 5 Classes

| Class | Label | Risk Band |
|---|---|---|
| 0 | Benign | 1 – 18 |
| 1 | Suspicious | 28 – 52 |
| 2 | Phishing | 58 – 78 |
| 3 | BEC (Business Email Compromise) | 74 – 89 |
| 4 | Malware | 80 – 95 |

### Feature Engineering (30 Meta-features)

The model consumes two inputs fused into one vector:

**Text document** — subject + sender name/domain + body text + URL hosts + attachment filenames. Bigrams and trigrams carry key signals ("wire transfer", "enable macros", "password expired").

**Engineered indicators** — 30 binary/continuous features:

| Feature | Signal |
|---|---|
| `meta:spf_fail / dkim_fail / dmarc_fail` | Authentication failures |
| `meta:spf_unaligned` | SPF pass for wrong domain |
| `meta:reply_to_differs` | Reply-To points elsewhere |
| `meta:url_offdomain` | Links go to different domain |
| `meta:url_anchor_mismatch` | Visible text ≠ actual URL |
| `meta:url_shortener` | URL shortener hides destination |
| `meta:attach_executable / macro / double_ext` | Weaponised attachments |
| `meta:no_received_chain` | Forged / injected relay path |
| `meta:html_only` | No plain-text alternative (common in phishing) |
| `meta:subject_caps` | SHOUTING SUBJECT |
| `meta:freemail_sender` | Gmail/Yahoo/Outlook as sender |
| `meta:punycode_sender` | IDN homograph domain |

### SHAP Explainability

Every prediction is accompanied by exact Shapley values over the fused feature vector, so the dashboard shows which tokens and which indicators drove the score — not just a number.

### Scoring — Log-Odds Combiner

Rules and the ML signal are combined in log-odds space (Naive Bayes evidence combination):

```
logit = PRIOR (−2.6) + Σ signal_weights
risk  = 100 / (1 + exp(−logit))         # logistic → [0, 100]
```

Each rule contributes a weight in log-odds units (e.g. DMARC pass = −1.60, DMARC fail = +2.30). The score saturates naturally — six strong signals cannot push past 99.9.

---

## Detection Pipeline

The agentic loop runs up to 5 layers, stopping early when evidence is conclusive:

### Layer 1 — Header & Content Analysis
- SPF / DKIM / DMARC / ARC validation
- Display-name brand impersonation (Levenshtein on confusable skeleton)
- Lookalike domain detection (Unicode confusables + edit distance)
- Reply-To and Return-Path divergence
- Zero-shot TF-IDF cosine similarity against anchors for: urgency, credential harvest, financial diversion, authority pressure, secrecy, malware lure

### Layer 2 — Relay Path Reconstruction
- GeoIP resolution of every public hop (MaxMind city + ASN)
- Anomaly detection: Tor exit nodes, VPN ranges, open relays, timing gaps, multi-country chains
- Origin attribution: compromised account / spoofed domain / anonymised infrastructure / direct actor

### Layer 3 — ML Classification
- TF-IDF + calibrated Logistic Regression (5 classes)
- Spear-phishing score via `engine/spear.py`
- SHAP feature attribution

### Layer 4 — Threat Intel Enrichment
- **AbuseIPDB**: abuse confidence score on relay IPs
- **VirusTotal**: URL and file hash lookup
- **DNSBL**: multi-list DNS blocklist check
- **WHOIS**: domain registration age (newly registered = direct-actor signal)

### Layer 5 — Link Detonation (optional)
- Playwright headless browser sandbox
- Screenshot + DOM capture
- Credential-page detection

### Verdict Assembly
```
build_verdict(signals, ml_prediction, coverage)
  → risk_score [0–100]
  → confidence [0–100]  (geometric mean of decisiveness × agreement × coverage)
  → label: benign / likely_benign / suspicious / indeterminate / phishing / bec / malware
  → MITRE ATT&CK techniques
  → recommended_action
```

### Campaign Clustering
Cases are linked by shared artefacts weighted by evidence strength:

| Artefact | Weight |
|---|---|
| Attachment SHA-256 | 1.00 |
| Sender address | 0.85 |
| URL host | 0.75 |
| Relay IP | 0.70 |
| Sender domain | 0.60 |
| Subject shape | 0.40 |
| ASN | 0.20 |

A cluster forms when the sum of shared-artefact weights ≥ 0.80.

---

## Project Structure

```
SIH2026-Targaryen/
├── backend/
│   ├── app/
│   │   ├── agent/          # Agentic investigation loop + narrative
│   │   ├── api/            # HTTP server, routes, SSE events
│   │   ├── blockchain/     # Keccak-256, custody chain, EVM client
│   │   ├── detection/      # Rule engine (log-odds combiner)
│   │   ├── engine/         # AI detector, spear-phishing scorer
│   │   ├── geoip/          # MaxMind resolver, relay path builder
│   │   ├── graph/          # Correlation, attribution, graph builder
│   │   ├── ingestion/      # EML parser (stdlib only)
│   │   ├── intel/          # AbuseIPDB, VirusTotal, DNSBL clients
│   │   ├── mitre/          # ATT&CK technique mapping
│   │   ├── ml/             # TF-IDF model, features, SHAP explain
│   │   ├── privacy/        # PII masking, retention purge
│   │   ├── report/         # PDF + mini-PDF generation
│   │   ├── sandbox/        # Playwright link detonation
│   │   ├── store/          # Neo4j CaseStore
│   │   ├── workflow/       # Triage, IOC export, SLA tracker
│   │   ├── config.py       # All settings (env-driven)
│   │   ├── pipeline.py     # Master ingest → investigate → save flow
│   │   └── schemas.py      # All Pydantic / dataclass models
│   └── requirements.txt
├── frontend/               # React 18 + Vite dashboard
│   └── src/
│       ├── lib/            # API client, types, live SSE
│       └── ...
├── chrome-extension/       # Manifest V3 extension
│   ├── background.js       # Service worker (analysis orchestrator)
│   ├── content/
│   │   ├── gmail.js        # Gmail content script
│   │   └── zoho.js         # Zoho Mail content script
│   ├── lib/utils.js        # Shared utilities
│   └── popup/              # Toolbar popup
├── data/
│   ├── demo/               # Bundled demo emails
│   ├── cache/              # Threat intel cache (AbuseIPDB, VT, DNSBL)
│   └── evidence/           # Custody trail (append-only JSONL)
├── ml/
│   └── models/             # Trained model (.joblib)
└── scripts/                # Training, dataset download, benchmarking
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| Node.js | 18+ |
| Neo4j Desktop | 2.x (local instance) |
| Chrome | 114+ (for extension) |

---

## Setup & Running

### 1. Neo4j

1. Open **Neo4j Desktop** → start your local instance
2. Note the connection URI (typically `neo4j://127.0.0.1:7687`)
3. Create a `.env` file in the repo root (see [Environment Variables](#environment-variables))

### 2. Backend

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Start the API server
python -m app.api.server
# → Running on http://127.0.0.1:8000
```

On first start, `CaseStore._init_schema()` automatically creates all Neo4j constraints, indexes, and the full-text index. Verify in Neo4j Browser:

```cypher
SHOW INDEXES
```

To load the bundled demo emails:

```bash
# Via the dashboard "Load demo" button, or programmatically:
curl -s http://127.0.0.1:8000/api/demo/seed -X POST
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### 4. Train or retrain the ML model (optional)



# Download datasets
python scripts/download_datasets_v2.py

# Train
python scripts/train_model_v2.py
# → writes ml/models/phish_tfidf_lr_real.joblib
```

### 5. Run tests

```bash
cd backend
python -m pytest tests/ -v
```

---

## Chrome Extension

### Install (developer mode)

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select `chrome-extension/`

### How it works

When you open an email in Gmail or Zoho Mail, the content script:

1. Tries to fetch the **full raw email** from Gmail's same-origin `?view=raw` endpoint (preserves all authentication headers for accurate analysis)
2. Falls back to a synthetic EML built from DOM-extracted fields if the raw fetch is unavailable
3. Submits to `POST /api/ingest` on the local backend
4. Polls `GET /api/cases/<id>` until analysis completes
5. Injects a colour-coded banner (green = benign, amber = suspicious/indeterminate, red = phishing/malware/BEC) with risk score, confidence %, and a "View in MailTrace →" link

### Supported mail clients

| Client | URL |
|---|---|
| Gmail | `https://mail.google.com/*` |
| Zoho Mail | `https://mail.zoho.com/*`, `https://mail.zoho.in/*` |

---

## Environment Variables

Create `.env` in the repo root:

```env
# Neo4j (required)
NEO4J_URI=neo4j://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
NEO4J_DATABASE=neo4j

# Network / API keys (all optional — backend degrades gracefully)
ALLOW_NETWORK=true
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ANTHROPIC_API_KEY=your_key          # for LLM narrative (claude-sonnet)
MAXMIND_LICENSE_KEY=your_key        # for GeoLite2 auto-download

# Blockchain (optional)
WEB3_RPC_URL=http://127.0.0.1:8545
MAILCUSTODY_ADDRESS=0x...
DEPLOYER_PRIVATE_KEY=0x...

# Alerting (optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
ALERT_MIN_RISK=50

# Behaviour
DEMO_MODE=false
EVIDENCE_RETENTION_DAYS=30
PII_MASKING=true
ORG_NAME=MailTrace SOC
```

All settings have safe defaults — the backend starts with zero configuration (Neo4j credentials excepted).

---

## API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Capabilities, DB stats, model status |
| `POST` | `/api/ingest` | Submit `.eml` file or raw bytes |
| `POST` | `/api/ingest/raw` | Submit raw email as plain text body |
| `GET` | `/api/cases` | Paginated case queue with filters |
| `GET` | `/api/cases/<id>` | Full case bundle (verdict, signals, graph, STIX) |
| `PATCH` | `/api/cases/<id>` | Update status / analyst / action |
| `POST` | `/api/cases/<id>/reinvestigate` | Re-run analysis on a stored case |
| `GET` | `/api/stats` | Dashboard counters |
| `GET` | `/api/campaigns` | Campaign roll-up |
| `GET` | `/api/search?q=` | Full-text search (Neo4j FTS / CONTAINS fallback) |
| `GET` | `/api/ioc/<value>` | All cases sharing an IOC |
| `GET` | `/api/events` | Server-Sent Events live stream |
| `POST` | `/api/demo/seed` | Load bundled demo emails |
| `GET` | `/api/retention` | Preview expired cases (dry run) |
| `POST` | `/api/retention` | Purge message content (keep verdict + hashes) |

---

## Key Design Decisions

**Stdlib HTTP server** — No uvicorn/FastAPI dependency. The server runs on `ThreadingHTTPServer` so the backend starts with `pip install -r requirements.txt` and nothing else.

**Log-odds scoring** — Evidence combines in log-odds space, not as a weighted point sum. Two independent weak signals compound the way Bayes says they should, and the score saturates rather than running past 100.

**Neo4j for persistence** — IOC nodes are shared across cases (`MERGE` on `(ioc_type, value)`), so `by_ioc` pivots are single-hop graph traversals, not SQL JOINs. Campaign clustering becomes a 2-hop Cypher query instead of an O(N²) Python loop.

**Confidence ≠ Risk** — Risk measures "how malicious?" Confidence measures "how sure are we?" They are computed independently. A 65/100 risk at 30% confidence is reported as INDETERMINATE — the system is honest about uncertainty rather than forcing a verdict.

**Custody chain** — The final case hash is anchored to an EVM chain (or simulated if no node is configured) using Keccak-256. Every re-investigation appends a new receipt, so the change in verdict is auditable.
