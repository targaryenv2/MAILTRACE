???# MailTrace ?? Complete Engineering & Forensic Architecture Documentation

**Smart India Hackathon 2026 | Technical Master Reference**  
*Document Version: 2.4 | Status: Production Verified | Date: September 2026*

---

## 1. System Vision & Core Tenets

MailTrace is an **Autonomous Email Threat Detection, Hop-by-Hop Origin Geolocation, and Cryptographic Forensic Intelligence Platform** engineered for modern Security Operations Centers (SOC).

### Core Engineering Tenets:
1. **Never Silently Fabricate Data**: As a legal and forensic evidence instrument, every response carries an explicit `source` tag (`"live"`, `"cached"`, `"computed"`, or `"unavailable"`). If an external API or network is missing, the system degrades honestly rather than inventing plausible figures.
2. **Fail-Closed Pre-Ingestion Hashing**: The raw message bytes are hashed with SHA-256 (`RootHash`) **before any parser or downstream logic touches them**. If a parser encounters a malformed email, the raw hash remains the uncorrupted anchor.
3. **Sequential 8-to-10 Layer Pipeline**: Each layer builds upon the verified facts of the preceding layer???from raw RFC byte parsing, through protocol cryptography, ML inference, and network tracing, to immutable smart contract ledger anchoring.
4. **Court Admissibility by Design**: Compliant with **Section 65B of the Indian Evidence Act (IEA)**, **US Federal Rule of Evidence 902(11)**, and **NIST SP 800-86**.

---

## 2. Exhaustive Layer-by-Layer Forensic Documentation

```
[ Ingested Email (.eml / .msg) ]
       ???
       ????????? [Layer 1: Forensic Ingestion & Root Hashing]
       ????????? [Layer 2: Protocol & Security Verification]
       ????????? [Layer 3: NLP & Machine Learning Engine]
       ????????? [Layer 4: Hop-by-Hop Origin Traceability]
       ????????? [Layer 5: Tier-2 Agentic SOC Investigation]
       ????????? [Layer 6: Identity Correlation & Threat Graph]
       ????????? [Layer 7: Blast Radius & SOC Operations]
       ????????? [Layer 8: Blockchain Custody & Forensic Reporting]
```

---

### Layer 1: Forensic Ingestion & Root Evidence Hashing

#### Files:
- `backend/app/ingestion/parser.py`
- `backend/app/ingestion/hasher.py`
- `backend/app/privacy/sanitizer.py`
- `backend/app/engine/qr.py`
- `backend/app/engine/steg.py`

#### Why It Exists:
In digital forensics, any modification (even accidental timestamp changes or charset normalizations) invalidates evidence in court. Layer 1 captures the raw binary state of the message and isolates all components before deeper analysis begins.

#### Technical Functionality & Implementation:
1. **Root Evidence Hashing (`hasher.py`)**:
   - Computes `SHA-256(raw_bytes)` as the foundational `RootHash` before any string decoding.
   - Generates deterministic case keys (`case_<hash[:16]>`).
2. **RFC 5322 & RFC 2045/2049 MIME Matrix Parser (`parser.py`)**:
   - Recursively unpacks multi-part MIME boundaries, inline images, nested `.eml` attachments, and encoded subject headers (`RFC 2047` base64/quoted-printable).
   - Extracts HTML DOM, plain-text bodies, header matrices, and visible anchor text mappings.
3. **PII Masking & Token Redaction (`sanitizer.py` / `redact.py`)**:
   - Replaces names, internal recipient emails, and phone numbers with cryptographic surrogate tokens (e.g. `k***n@meridian-labs.org [#a71b8e]`) when exported to external APIs or third-party SIEMs under DPDP/GDPR rules.
4. **Quishing & QR Matrix Extraction (`qr.py`)**:
   - Scans image attachments (`.png`, `.jpg`, `.bmp`) using OpenCV image preprocessing and PyZbar matrix decoding to discover concealed credential phishing URLs embedded in QR graphics.
5. **Steganography Chi-Square Analysis (`steg.py`)**:
   - Executes statistical chi-square distribution tests (`scipy.stats.chisquare`) on Least Significant Bits (LSB) to detect hidden payloads and encrypted exfiltration data within image files.

---

### Layer 2: Protocol & Security Verification

#### Files:
- `backend/app/detection/engine.py`
- `backend/app/engine/rules.py`
- `backend/app/engine/spoof.py`
- `backend/app/engine/arc.py`

#### Why It Exists:
Attackers frequently forge sender identities. Layer 2 verifies cryptographic provenance at the DNS and mail transfer protocol level to catch domain spoofing, relay hijacking, and visual display-name deception.

#### Technical Functionality & Implementation:
1. **Cryptographic Protocol Validation (`rules.py` / `dnspython`)**:
   - **SPF (RFC 7208)**: Queries sending domain DNS TXT records to confirm whether the connecting relay IP is an authorized sender.
   - **DKIM (RFC 6376)**: Validates RSA cryptographic signatures against the selector public key in DNS.
   - **DMARC (RFC 7489)**: Verifies SPF/DKIM domain alignment against the published DMARC policy (`none`, `quarantine`, `reject`).
   - **ARC (RFC 8617)**: Validates Authenticated Received Chains to detect legitimate mail forwarding vs. malicious alteration.
2. **Homoglyph & Punycode Spoofing Detection (`spoof.py`)**:
   - Normalizes Unicode characters and checks for mixed-script attacks (e.g., replacing Latin `o` with Cyrillic `??` in `micros0ft-verify.com` or `paypa1.com`).
   - Decodes `xn--` Punycode domains and flags lookalikes against high-value brand databases.
3. **Display-Name Impersonation**:
   - Compares the visible sender string (e.g. `"CEO Jane Doe"`) against the actual envelope return-path (`attacker@free-mail.top`) to detect executive impersonation.

---

### Layer 3: NLP & Machine Learning Classification Engine

#### Files:
- `backend/app/ml/predict.py`
- `backend/app/ml/features.py`
- `backend/app/ml/model.py`
- `backend/app/ml/explain.py`
- `backend/app/engine/spear.py`
- `backend/app/engine/ai_detector.py`
- `ml/models/phish_tfidf_lr_real.joblib`

#### Why It Exists:
Rule-based systems miss zero-day social engineering lures. Layer 3 evaluates semantic text patterns, structural urgency, and linguistic intent across 5 granular threat classes.

#### Technical Functionality & Implementation:
1. **5-Class Multinomial Architecture**:
   - Classes: `0: BENIGN`, `1: SUSPICIOUS`, `2: PHISHING`, `3: BEC (Business Email Compromise)`, `4: MALWARE`.
2. **FeatureUnion (Text + 21 Structural Features)**:
   - **TF-IDF N-grams**: 50,000 max features across unigrams, bigrams, and trigrams (`ngram_range=(1,3)`), with sublinear term-frequency scaling.
   - **21 Domain-Specific Structural Features**: URL density, IP-literal links, file extension risk (`.exe`, `.iso`, `.hta`, `.vbs`), financial trigger keywords (wire transfer, invoice, payroll, gift cards), urgency anchors, and recipient exposure ratios.
3. **Isotonic Calibration (`CalibratedClassifierCV`)**:
   - Applies 5-fold cross-validated isotonic regression so that model probabilities represent true empirical risk (preventing overconfident raw logistic outputs).
4. **Exact Closed-Form SHAP Explainability (`explain.py`)**:
   - Calculates exact feature contribution weights:
     $$\phi_{kj} = w_{kj} \times (x_j - E[x_j])$$
   - Satisfies the Local Accuracy Axiom: $f_k(x) = E[f_k] + \sum \phi_{kj}$.
   - Renders red/green token importance highlights in both the web console and court PDF reports.
5. **Word-Level Bigram AI Text Detector (`ai_detector.py`)**:
   - Evaluates text perplexity and sentence-level burstiness against a baseline of 20,000 human corporate emails.
   - LLM-generated emails exhibit low perplexity ($<50$) and flat burstiness, whereas human emails show high perplexity ($>400$) and irregular burstiness.
6. **Low-Keyword Spearphishing Engine (`spear.py`)**:
   - Catches sophisticated CEO fraud and vendor compromise that avoid overt trigger words by detecting subtle authority assertion, sensitive requests, and buried links.

---

### Layer 4: Hop-by-Hop Origin Traceability & Geolocation

#### Files:
- `backend/app/geoip/resolver.py`
- `backend/app/engine/trace.py`
- `backend/app/engine/anomalies.py`
- `data/geoip/city.mmdb` & `asn.mmdb`

#### Why It Exists:
Email headers can have forged `From:` and `Reply-To:` lines, but every legitimate intermediate MTA stamps an immutable `Received:` header. Layer 4 traces the packet journey backwards to locate the true origin server.

#### Technical Functionality & Implementation:
1. **Bottom-Up SMTP Relay Reconstruction (`trace.py`)**:
   - Parses the complete `Received:` header stack chronologically from client injection to corporate MX gateway.
   - Identifies the earliest reliable public IP address, filtering out internal RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
2. **Local Binary GeoIP2 Resolution (`resolver.py`)**:
   - Queries local MaxMind GeoLite2 binary databases (`city.mmdb` ~132MB and `asn.mmdb` ~11.8MB) in memory for sub-millisecond country, city, coordinates, Autonomous System Number (ASN), and ISP lookup.
3. **Relay Anomaly & Anonymizer Classification (`anomalies.py`)**:
   - Detects Tor exit nodes, bulletproof data centers, residential proxies, cloud VPS relays (AWS/DigitalOcean/Hetzner acting as user MTAs), and reverse-DNS pointer (`PTR`) mismatches.

---

### Layer 5: Tier-2 Agentic SOC Investigation & Live OSINT

#### Files:
- `backend/app/agent/loop.py`
- `backend/app/intel/client.py`
- `backend/app/intel/dns_client.py`
- `backend/app/sandbox/detonate.py`

#### Why It Exists:
Automates the investigative reasoning a human Tier-2 SOC analyst performs when evaluating suspicious indicators against external global intelligence feeds.

#### Technical Functionality & Implementation:
1. **Autonomous Planning Loop (`loop.py`)**:
   - Evaluates accumulated evidence after each step. Skips costly external API queries if header cryptography or ML classification is already conclusive ($<20$ or $>80$), preserving API rate limits.
2. **VirusTotal API v3 (`client.py`)**:
   - Queries live file hashes and URL reputations across 70+ antivirus and web engines. Identifies zero-day unindexed URLs.
3. **AbuseIPDB Threat Scoring**:
   - Fetches historical abuse confidence percentages, report volumes, and threat categories for suspect relay IPs.
4. **WHOIS Domain Age & Telemetry**:
   - Extracts domain registration dates and registrar contacts. Automatically escalates risk if a domain was created $<30$ days prior to the attack.
5. **Spamhaus DNSBL Real-Time Blocklists (`dns_client.py`)**:
   - Queries `zen.spamhaus.org`, `bl.spamcop.net`, and `b.barracudacentral.org` across 3 threat zones.
6. **Headless Browser Detonation Sandbox (`detonate.py`)**:
   - Playwright headless Chromium sandbox visits extracted links in an isolated environment, logging HTTP redirects, credential forms, and downloading landing page screenshots.

---

### Layer 6: Identity Correlation & Threat Campaign Graph

#### Files:
- `backend/app/graph/correlate.py`
- `backend/app/graph/attribution.py`
- `backend/app/mitre/attack.py`
- `frontend/src/components/GraphView.tsx`

#### Why It Exists:
Phishing attacks are rarely isolated; they are organized campaigns reusing infrastructure across multiple targets. Layer 6 clusters related cases into campaign webs.

#### Technical Functionality & Implementation:
1. **Jaccard Indicator Clustering (`correlate.py`)**:
   - Correlates cases based on shared attachment SHA-256 hashes (weight 1.0), sender domains (weight 0.85), URL hosts (weight 0.75), relay IPs (weight 0.70), and ASNs (weight 0.20).
2. **Force-Directed Graph Visualization (`GraphView.tsx`)**:
   - Interactive Canvas/SVG force-directed layout rendering active cases, domains, IPs, senders, and files simultaneously with zoom, pan, and node filtering.
3. **MITRE ATT&CK?? Enterprise Matrix Mapping (`attack.py`)**:
   - Automatically maps detected signals to official MITRE techniques:
     - `T1566 / T1566.002`: Phishing / Spearphishing Link
     - `T1598.003`: Phishing for Information
     - `T1583.001`: Acquire Infrastructure (Domains)
     - `T1036`: Masquerading (Homoglyphs)
     - `T1090.003`: Tor Anonymization Proxy

---

### Layer 7: Blast Radius & SOAR Response Orchestration

#### Files:
- `backend/app/workflow/triage.py`
- `backend/app/workflow/blast_radius.py`
- `backend/app/workflow/takedown.py`
- `backend/app/alerts/notifier.py`
- `backend/app/workflow/stix_export.py`

#### Why It Exists:
Detection without rapid containment is ineffective. Layer 7 calculates organizational exposure and triggers automated response playbooks.

#### Technical Functionality & Implementation:
1. **Mailbox Exposure & Blast Radius Calculation (`blast_radius.py`)**:
   - Evaluates total internal recipients exposed, click telemetry, and credential submission status across the organization.
2. **RFC 2142 Automated Domain Abuse Takedowns (`takedown.py`)**:
   - Formulates ready-to-send legal abuse notifications directed to the registrar's abuse contact (`abuse@registrar.com`), complete with forensic headers, timestamps, and SHA-256 digests.
3. **Real-Time SOC Alerting (`notifier.py`)**:
   - Dispatches formatted Discord webhook embeds with color-coded severity, key forensic findings, PII-masked headers, and recommended response playbooks.
4. **SIEM & Threat Feed Export (`stix_export.py`)**:
   - Exports structured JSON bundles conforming to **STIX 2.1** and **MISP Core** standards for ingestion into enterprise SIEMs (Splunk, Microsoft Sentinel, QRadar).

---

### Layer 8: Blockchain Chain of Custody & Legal Reporting

#### Files:
- `contracts/MailCustody.sol`
- `backend/app/blockchain/client.py`
- `backend/app/blockchain/abi.py`
- `backend/app/blockchain/keccak.py`
- `backend/app/report/pdf.py`

#### Why It Exists:
Provides tamper-evident proof that forensic evidence has not been altered post-investigation, satisfying court admissibility requirements.

#### Technical Functionality & Implementation:
1. **Solidity Smart Contract (`MailCustody.sol`)**:
   - Deployed on EVM networks (Ganache, Polygon, Ethereum) using Solidity `^0.8.20`.
   - Structures append-only hash chains where each entry embeds the `keccak256` digest of the previous entry:
     $$\text{EntryHash}_n = \text{keccak256}(\text{caseKey} \parallel \text{payloadHash} \parallel \text{EntryHash}_{n-1})$$
   - Immutable: contains no `delete`, `update`, or `selfdestruct` opcodes.
2. **Deterministic In-Memory & Local EVM Fallback (`client.py`)**:
   - If no live JSON-RPC node is available, computes the exact `keccak256` chain locally and writes to `custody_trail.jsonl`, stamping receipts with `simulated: True`.
   - When Ganache is active on `http://127.0.0.1:8545`, automatically broadcasts live `eth_sendRawTransaction` calls and records real block numbers.
3. **Section 65B Indian Evidence Act Court-Admissible PDF (`pdf.py`)**:
   - Generates multi-page ReportLab PDF dossiers containing:
     - Executive summary, disposition, and risk scores.
     - Complete RFC header matrix and authentication certificates.
     - SHAP feature token attributions.
     - Hop-by-hop relay route tables with geolocation and ASNs.
     - Cryptographic Merkle chain of custody audit trail and transaction hashes.

---

## 3. Machine Learning Model & Training Dataset Provenance

### Dataset Sourcing & Deduplication (Page 13)
* **Total Corpus Size**: **68,310 verified samples** post-semantic TF-IDF deduplication ($0.85$ cosine similarity threshold).
* **Train / Test Split**: 54,646 Training samples ($80\%$) vs. 13,664 Held-out Test samples ($20\%$).
* **Sources**:
  * *Benign (21,052 samples)*: Apache SpamAssassin Easy Ham, CMU Enron Sent Mail, Ling-Spam.
  * *Suspicious (13,803 samples)*: SpamAssassin Spam 1+2, Enron Spam Labels, Waterloo TREC 2007.
  * *Phishing (15,008 samples)*: Nazario Phishing Corpus, PhishTank Verified Feed, IWSPA-2018.
  * *BEC (8,514 samples)*: Enron BEC-pattern mined + FBI IC3 category augmentation.
  * *Malware (9,933 samples)*: MalwareDB Corpus + multi-vector lure augmentation.

---

## 4. Test Suite Parity (43 / 43 Passing Tests)

Verified via `pytest tests/ -v`:
1. `TestDataIntegrity` (6 tests): Zero train/test overlap, dataset scale, class distribution balance.
2. `TestModelBehavior` (8 tests): Safe keyword handling, BEC/Phishing/Malware discrimination, probability calibration.
3. `TestAIDetector` (5 tests): Perplexity separation delta ($>50$ points), burstiness ranges, edge-case text handling.
4. `TestGeoIP` (8 tests): Binary MMDB reader verification, live IP resolution, Tor exit node detection.
5. `TestNLPSignals` (4 tests): Cosine similarity anchor weights, clean email noise floor.
6. `TestEndToEnd` (12 tests): Sub-200ms end-to-end execution, SHA-256 hash preservation, dangerous attachment malware classification.

---

## 5. Active Configuration & Service Reference

### Environment Variables (`backend/.env`):
- `ALLOW_NETWORK=true`: Master switch for external threat intelligence.
- `ALLOW_DETONATION=true`: Enables Playwright sandbox detonation.
- `DEMO_MODE=false`: Enables live analysis pipeline over static snapshots.
- `VIRUSTOTAL_API_KEY`: Active live v3 API key (`[REDACTED]`).
- `ABUSEIPDB_API_KEY`: Active live API key (`[REDACTED]`).
- `DISCORD_WEBHOOK_URL`: Active SOC channel webhook endpoint.
- `WEB3_RPC_URL=http://127.0.0.1:8545`: Local Ganache EVM RPC connection.
- `CHAIN_ID=1337`: Ganache EVM Chain ID.
- `MAILCUSTODY_ADDRESS=0x5CDf38e3eC1D80640F7436bb05CF2d12A0C869bf`: Deployed smart contract address.
- `DEPLOYER_PRIVATE_KEY=0xbb69b0ab7a0fd55dfe74a4bbab41392c9b99286b617a3d72e99bb0ed3140ae2d`: Pre-funded deployer account key.

---

## 6. How to Run and Verify the Full System

### Step 1: Start Ganache EVM Node
```bash
npx ganache --host 0.0.0.0 --port 8545
```

### Step 2: Start Backend API Server
```bash
.venv\Scripts\python.exe -m app.api.server --host 127.0.0.1 --port 8000
```
*Interactive Swagger UI*: `http://127.0.0.1:8000/docs`

### Step 3: Start Frontend SOC Console
```bash
cd frontend
npm run dev
```
*Web Console*: `http://localhost:5173/`

### Step 4: Run the Complete Automated Test Suite
```bash
.venv\Scripts\pytest tests/ -v
```
