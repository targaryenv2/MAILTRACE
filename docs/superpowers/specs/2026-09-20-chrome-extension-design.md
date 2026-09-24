# Chrome Extension: MailTrace Gmail & Zoho Mail Integration

**Date:** 2026-09-20  
**Status:** Approved — ready for implementation  
**Approach:** Manifest V3 · Content scripts + Background service worker  

---

## 1. Purpose

A Chrome extension that watches Gmail and Zoho Mail for opened emails, extracts the message from the DOM, submits it to the local MailTrace backend (`localhost:8000`), and injects a colored inline threat banner at the top of the email reading pane showing the verdict, risk score, and a link to the full investigation.

---

## 2. File Structure

```
chrome-extension/
├── manifest.json          # MV3 manifest: permissions, host_permissions, content scripts, service worker
├── background.js          # Service worker: ingest API call, polling, session cache
├── content/
│   ├── gmail.js           # Gmail DOM watcher, EML extractor, banner injector
│   └── zoho.js            # Zoho Mail DOM watcher, EML extractor, banner injector
├── popup/
│   ├── popup.html         # Toolbar popup: backend connection status + analysis count
│   └── popup.js           # Checks GET /api/health, shows status
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 3. Manifest (MV3)

```json
{
  "manifest_version": 3,
  "name": "MailTrace Threat Scanner",
  "version": "1.0.0",
  "description": "Inline phishing detection for Gmail and Zoho Mail via MailTrace",
  "permissions": ["storage"],
  "host_permissions": [
    "https://mail.google.com/*",
    "https://mail.zoho.com/*",
    "https://mail.zoho.in/*",
    "http://localhost:8000/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/*"],
      "js": ["content/gmail.js"],
      "run_at": "document_idle"
    },
    {
      "matches": ["https://mail.zoho.com/*", "https://mail.zoho.in/*"],
      "js": ["content/zoho.js"],
      "run_at": "document_idle"
    }
  ],
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  }
}
```

---

## 4. Data Flow

```
content script (gmail.js / zoho.js)
  1. MutationObserver fires when email reading pane opens
  2. Extracts: From, To (unused), Subject, Date, body text
  3. Strips quoted replies before extracting body
  4. Builds fingerprint = btoa(From + Subject + Date) as dedup key
  5. Injects "Analyzing…" placeholder banner (grey)
  6. chrome.runtime.sendMessage({action:"analyze", fields, fingerprint})

background.js (service worker)
  7. Checks chrome.storage.session cache by fingerprint
     → hit: returns cached {verdict, risk_score, confidence, case_number}
     → miss: continues
  8. Builds RFC 822 EML string from extracted fields
  9. POST http://localhost:8000/api/ingest (multipart/form-data, file=eml blob)
  10. Receives {cases:[{case_number}]} or {case:{case_number}}
  11. Polls GET http://localhost:8000/api/cases/{case_number} every 500ms
      until case.status !== "analyzing"  (max 30s / 60 attempts)
  12. Stores result in chrome.storage.session
  13. Sends result back to content script tab

content script (continued)
  14. Replaces placeholder banner with colored verdict banner
  15. Removes banner when user navigates to next email
```

---

## 5. Gmail DOM Selectors

| Field | Selector | Notes |
|---|---|---|
| Email open | `.a3s.aiL` appearing in DOM | Most stable across Gmail deploys |
| From address | `.cf[email]` attribute | Fallback: `.gD[email]` |
| From name | `.cf span.go` | Display name |
| Subject | `.hP` | Thread subject line |
| Date | `.g3` or `[data-tooltip]` on timestamp span | Full date string |
| Body | `.a3s.aiL innerText` after removing `.gmail_quote` | Strips quoted thread |
| Message-ID | Not in DOM | Use fingerprint as cache key |

**Trigger logic:** `MutationObserver` on `document.body` with `subtree: true`, `childList: true`. On each mutation batch, query for `.a3s.aiL` nodes not yet processed (tracked via a `WeakSet`).

---

## 6. Zoho Mail DOM Selectors

| Field | Selector | Notes |
|---|---|---|
| Email open | `.mail-read-pane` or `#readPane` becoming non-empty | |
| From address | `.zmail-from .addr-text[title]` title attr | Fallback: `.fromAddress span` |
| From name | `.zmail-from .fromName` | |
| Subject | `.mail-subject-name` | Fallback: `.subject-text` |
| Date | `.mail-date-time[title]` title attr | Full timestamp |
| Body | `.mail-body-content innerText` | Fallback: `#mailbody innerText` |
| Navigation | `hashchange` event | Detects email-to-email navigation |

Both `mail.zoho.com` and `mail.zoho.in` use the same DOM structure; one content script covers both.

---

## 7. EML Reconstruction

The background service worker assembles this before calling `/api/ingest`:

```
From: {fromName} <{fromAddress}>
To: analyst@mailtrace.local
Subject: {subject}
Date: {date}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

{bodyText}
```

**What this gives the backend:**
- L1 (headers): From, Subject, Date — fully parsed
- L2 (ML): body text — full classification
- L3 (attachments): none (not in DOM)
- L4 (auth): SPF/DKIM/DMARC return `none` — `Received` headers not available in webmail DOM; backend policy never invents values
- L5 (relay): no `Received` hops — origin will be `unavailable`
- L6 (URLs): embedded links extracted from body text — threat intel lookup runs normally
- L7–L10: run normally on available data

The analyst sees exactly what was available, with `source: unavailable` on fields that require raw headers.

---

## 8. Banner Injection

The banner is injected as the **first child** of the email reading pane, inside a **Shadow DOM host** to prevent CSS bleed from Gmail/Zoho stylesheets.

**States:**

| State | Background | Text color | Content |
|---|---|---|---|
| Analyzing | `#F1F5F9` | `#64748B` | `🛡 MailTrace: Analyzing…` |
| Clean / Benign / Likely Benign | `#F0FDF4` | `#16A34A` | `✓ BENIGN  12/100  Confidence: 94%  View in MailTrace →` |
| Suspicious / Indeterminate | `#FEF3C7` | `#D97706` | `⚠ SUSPICIOUS  55/100  Confidence: 67%  View in MailTrace →` |
| Phishing / Malware / BEC | `#FEF2F2` | `#DC2626` | `✕ PHISHING  87/100  Confidence: 91%  View in MailTrace →` |
| Timeout (30s) | `#F1F5F9` | `#64748B` | `MailTrace: Analysis timed out — open MailTrace to check manually` |
| Backend unreachable | `#F1F5F9` | `#64748B` | `MailTrace: Backend offline (localhost:8000)` |

**"View in MailTrace →"** opens `http://localhost:5173` in a new tab. The main app shows all analyzed cases in the queue panel.

**Lifecycle:** Banner is removed when:
- Gmail: a new `.a3s.aiL` node is detected (next email opened)
- Zoho: `hashchange` event fires

---

## 9. Toolbar Popup

`popup.html` shows:
- Connection indicator: calls `GET http://localhost:8000/api/health` — green dot "Connected" or red dot "Offline"
- Total analyses this session (from `chrome.storage.session`)
- Link: "Open MailTrace" → `http://localhost:5173`

Lightweight — no framework, plain HTML + vanilla JS.

---

## 10. Caching

`chrome.storage.session` (cleared when browser closes):
- Key: `mt_${fingerprint}`
- Value: `{verdict, risk_score, confidence, case_number, analyzedAt}`
- TTL: session only — no persistence across browser restarts

This prevents re-submitting the same email every time the user clicks back to it in a thread.

---

## 11. Error Handling

| Scenario | Behaviour |
|---|---|
| Backend not running | Banner: "Backend offline (localhost:8000)" |
| Ingest returns non-200 | Banner: "Analysis failed — open MailTrace for details" |
| Polling times out at 30s | Banner: "Analysis timed out — open MailTrace to check manually" |
| DOM selectors find no data | Skip analysis; no banner injected |
| Content script runs on compose window | Guard: only trigger on read pane selectors |

---

## 12. Loading the Extension (Dev Mode)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select `chrome-extension/` folder
4. Navigate to Gmail or Zoho Mail — the extension is active

No build step required. Plain ES2020 JavaScript, no bundler needed.
