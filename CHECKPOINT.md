???# MailTrace ?? Technical Checkpoint & Complete System Reference

**Smart India Hackathon 2026 | Technical Reference & Operational Checkpoint**  
*Compiled: September 2026*

---

## 1. Executive Summary & Architecture
MailTrace is an **AI-powered email threat detection, hop-by-hop origin geolocation, and cryptographic forensic intelligence platform** built for Security Operations Centers (SOC).

Every incoming `.EML` / `.MSG` artifact traverses an autonomous **8-to-10 Layer Forensic Pipeline**. An immutable SHA-256 `RootHash` is generated prior to parsing, travels across all layers, and is permanently anchored on an EVM blockchain smart contract (`MailCustody.sol`), providing a court-admissible electronic record (compliant with Section 65B of the Indian Evidence Act and US Federal Rule 902(11)).

---

## 2. Forensic Pipeline Layers (Explicit Technical Breakdown)

### Layer 1: Forensic Ingestion & Root Evidence Hashing
- **Files**: `backend/app/ingestion/parser.py`, `hasher.py`, `sanitizer.py`, `qr.py`, `steg.py`
- **Core Capabilities**:
  - Raw byte pre-ingestion SHA-256 fingerprinting before any parsing (`RootHash`).
  - RFC 5322 & RFC 2045/2049 MIME matrix parser extracting headers, HTML/plain bodies, and nested attachments recursively.
  - PII and sensitive token masking (emails, names, phone numbers) before processing.
  - Quishing detection: QR matrix localization and extraction via OpenCV (`cv2`), PyZbar, and Pillow (PIL).
  - Steganography testing: Chi-square LSB statistical bit analysis (`scipy.stats.chisquare`).

### Layer 2: Protocol & Authentication Verification
- **Files**: `backend/app/detection/engine.py`, `spoof.py`, `arc.py`, `rules.py`
- **Core Capabilities**:
  - Cryptographic validation of SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489), and ARC (RFC 8617) protocols.
  - DNS TXT record querying and alignment verification (`dnspython`).
  - Unicode homoglyph, Punycode domain decoding, and display-name impersonation detection.

### Layer 3: NLP & Machine Learning Classification Engine
- **Files**: `backend/app/ml/predict.py`, `features.py`, `model.py`, `explain.py`, `engine/spear.py`, `ai_detector.py`
- **Core Capabilities**:
  - **5-Class Multinomial Classifier**: `BENIGN` (0), `SUSPICIOUS` (1), `PHISHING` (2), `BEC` (3), `MALWARE` (4).
  - **FeatureUnion Architecture**: `TfidfVectorizer` (50,000 features, 1-3 n-grams, sublinear TF) combined with **21 domain-specific structural features** (attachment context, URL entropy, financial urgency patterns, execution instructions).
  - **CalibratedClassifierCV**: Isotonic calibration ($cv=5$) preventing overconfident probability estimates.
  - **SHAP Explainability**: Exact closed-form Shapley feature attribution ($\phi_{kj} = w_{kj} \times (x_j - E[x_j])$) providing per-token weights for court evidence.
  - **AI-Generated Text Detection**: Word-level bigram language model evaluating perplexity and burstiness separation (human perplexity $> 400$ vs AI $< 50$).
  - **Spearphishing Engine**: Regex pattern matcher catching low-keyword targeted spearphish lures.

### Layer 4: Hop-by-Hop Origin Traceability & Geolocation
- **Files**: `backend/app/geoip/resolver.py`, `engine/trace.py`, `anomalies.py`
- **Core Capabilities**:
  - Bottom-up SMTP `Received:` relay chain reconstruction (RFC 5321).
  - Offline MaxMind binary database resolution (`data/geoip/city.mmdb` ~132MB, `asn.mmdb` ~11.8MB).
  - Tor exit node, bulletproof hosting, proxy, and VPN anomaly detection.

### Layer 5: Tier-2 Agentic SOC Investigation & Live OSINT
- **Files**: `backend/app/agent/loop.py`, `intel/client.py`, `sandbox/detonate.py`
- **Core Capabilities**:
  - Autonomous state machine loop sequencing deterministic and network-bound checks.
  - **VirusTotal API v3**: Live malicious URL engine detection tallies and zero-day status.
  - **AbuseIPDB API**: IP abuse confidence scoring and global report counts.
  - **WHOIS Telemetry**: Domain creation date, domain age (flagging $< 30$ days), and registrar data.
  - **Spamhaus DNSBL**: Real-time multi-zone IP blocklist lookups.
  - **Headless Browser Detonation**: Playwright link sandbox for form and redirect analysis.

### Layer 6: Identity Correlation & Campaign Graph
- **Files**: `backend/app/graph/correlate.py`, `attribution.py`, `frontend/src/components/GraphView.tsx`
- **Core Capabilities**:
  - Multi-case Jaccard similarity clustering across shared domains, IPs, senders, and file digests.
  - Force-directed Canvas/SVG graph with interactive zoom, panning, and MITRE ATT&CK?? Enterprise mapping.

### Layer 7: Blast Radius & SOAR Response Orchestration
- **Files**: `backend/app/workflow/triage.py`, `blast_radius.py`, `takedown.py`, `alerts/notifier.py`
- **Core Capabilities**:
  - Enterprise mailbox exposure scoping and clawback calculation.
  - Auto-generation of RFC 2142 domain abuse takedown notices for registrars and hosting providers.
  - Real-time Discord SOC alerts with rich embed cards and PII-masked headers.
  - STIX 2.1 & MISP JSON threat intelligence exports.

### Layer 8: Blockchain Custody & Court-Admissible Reporting
- **Files**: `contracts/MailCustody.sol`, `backend/app/blockchain/client.py`, `report/pdf.py`
- **Core Capabilities**:
  - Solidity `^0.8.20` smart contract (`MailCustody.sol`) managing append-only hash chains.
  - Web3.py JSON-RPC connection to EVM nodes (Ganache / Hardhat / Sepolia / Polygon).
  - Automatic fallback to deterministic local Keccak-256 Merkle simulator when offline.
  - Section 65B Indian Evidence Act compliant PDF generation via ReportLab.

---

## 3. Dataset & ML Corpus Provenance (Page 13)
- **Total Corpus Size**: **68,310 verified samples** post semantic TF-IDF deduplication (0.85 cosine similarity threshold).
- **Split**: 54,646 Training samples (80%), 13,664 Held-out Testing samples (20%).
- **Sources**: Apache SpamAssassin (Easy Ham & Spam 1+2), CMU/Kaggle Enron Email Dataset, Waterloo TREC 2007, Nazario Phishing Corpus, PhishTank Live Feed, IWSPA-2018, Ling-Spam, FBI IC3 BEC mined patterns, and MalwareDB.

---

## 4. Test Suite Parity (43 / 43 Tests Passed)
Verified via `pytest tests/ -v`:
- `TestDataIntegrity` (6 tests): Zero train/test overlap, dataset balance, source diversity.
- `TestModelBehavior` (8 tests): Attachment context, BEC/Phishing/Malware classification, probability normalization.
- `TestAIDetector` (5 tests): Human vs. AI perplexity delta ($>50$ points), burstiness ranges, short text handling.
- `TestGeoIP` (8 tests): Binary MMDB resolution, live IP resolution, Tor exit node detection.
- `TestNLPSignals` (4 tests): Cosine similarity anchor weights, clean email noise floor.
- `TestEndToEnd` (12 tests): Sub-200ms pipeline execution across all demo emails, SHA-256 hash integrity.

---

## 5. Active Environment & Configuration Reference

### Backend (`backend/.env`)
- `ALLOW_NETWORK=true`
- `ALLOW_DETONATION=true`
- `DEMO_MODE=false`
- `VIRUSTOTAL_API_KEY=[REDACTED]` (Active)
- `ABUSEIPDB_API_KEY=[REDACTED]` (Active)
- `DISCORD_WEBHOOK_URL=https://discordapp.com/api/webhooks/...` (Active)
- `WEB3_RPC_URL=http://127.0.0.1:8545` (Active Ganache connection)
- `CHAIN_ID=1337`
- `MAILCUSTODY_ADDRESS=0x5CDf38e3eC1D80640F7436bb05CF2d12A0C869bf` (Deployed)
- `DEPLOYER_PRIVATE_KEY=0xbb69b0ab7a0fd55dfe74a4bbab41392c9b99286b617a3d72e99bb0ed3140ae2d`

---

## 6. How to Run & Verify

1. **Start Blockchain (Ganache)**:
   ```bash
   npx ganache --host 0.0.0.0 --port 8545
   ```
2. **Start Backend Server**:

   ```bash
   .venv\Scripts\python.exe -m app.api.server --host 127.0.0.1 --port 8000
   ```
3. **Start Frontend SOC Console**:
   ```bash
   cd frontend && npm run dev
   ```
4. **Execute Full Test Suite**:
   ```bash
   .venv\Scripts\pytest tests/ -v
   ```
