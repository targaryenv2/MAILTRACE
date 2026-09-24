# Chrome Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Chrome MV3 extension that detects opened emails in Gmail and Zoho Mail, submits them to the local MailTrace backend, and injects a colored threat-verdict banner inline.

**Architecture:** A background service worker owns all API I/O (ingest + polling + session cache). Content scripts own DOM watching, EML field extraction, and banner injection via Shadow DOM. Pure utility functions are shared via `lib/utils.js` loaded with `importScripts()` in the service worker and inlined in content scripts.

**Tech Stack:** Chrome Manifest V3, vanilla ES2020, Node.js (for unit tests and icon generation — no npm packages required), `chrome.storage.session`, `chrome.runtime.sendMessage`.

**Spec:** `docs/superpowers/specs/2026-09-20-chrome-extension-design.md`

## Global Constraints

- Manifest version: 3
- No build step, no bundler, no npm packages in the extension itself
- Backend URL: hardcoded `http://localhost:8000` — no config UI
- Frontend URL: hardcoded `http://localhost:5173` for "View in MailTrace" link
- Polling: 500 ms interval, 60 attempts max (30 s timeout)
- Cache: `chrome.storage.session` — clears on browser close
- Cache key format: `mt_` + fingerprint (alphanumeric, max 40 chars)
- Shadow DOM mode: `closed` — prevents page styles bleeding into banner
- Banner injected as first child of email container via `data-mailtrace-banner` attribute
- All verdict values from spec section 8: `phishing`, `malware`, `bec` → red; `suspicious`, `indeterminate` → amber; `clean`, `benign`, `likely_benign` → green
- Node.js unit tests require no test framework — plain assertions with `process.exit(1)` on failure

---

### Task 1: Scaffold — directory structure, manifest, icons

**Files:**
- Create: `chrome-extension/manifest.json`
- Create: `chrome-extension/scripts/generate_icons.js`
- Create (generated): `chrome-extension/icons/icon16.png`, `icon48.png`, `icon128.png`
- Create (empty stubs): `chrome-extension/background.js`, `chrome-extension/content/gmail.js`, `chrome-extension/content/zoho.js`, `chrome-extension/lib/utils.js`, `chrome-extension/popup/popup.html`, `chrome-extension/popup/popup.js`

**Interfaces:**
- Produces: A loadable Chrome extension skeleton (no functionality yet — loading it in Chrome should show the icon without errors)

- [ ] **Step 1: Create the directory tree**

```bash
mkdir -p chrome-extension/content
mkdir -p chrome-extension/lib
mkdir -p chrome-extension/popup
mkdir -p chrome-extension/icons
mkdir -p chrome-extension/scripts
```

- [ ] **Step 2: Write `chrome-extension/manifest.json`**

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

- [ ] **Step 3: Write `chrome-extension/scripts/generate_icons.js`**

This script generates solid blue (#2563EB) PNG files using only Node.js built-ins (no npm).

```js
#!/usr/bin/env node
const zlib = require('zlib');
const fs   = require('fs');
const path = require('path');

function crc32(buf) {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = t[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const t = Buffer.from(type, 'ascii');
  const body = Buffer.concat([t, data]);
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, t, data, crc]);
}

function makePNG(size, r, g, b) {
  const sig = Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 2; // 8-bit RGB
  const raw = Buffer.alloc(size * (size * 3 + 1));
  for (let y = 0; y < size; y++) {
    const row = y * (size * 3 + 1);
    raw[row] = 0; // filter: None
    for (let x = 0; x < size; x++) {
      raw[row + 1 + x*3] = r;
      raw[row + 1 + x*3+1] = g;
      raw[row + 1 + x*3+2] = b;
    }
  }
  const idat = zlib.deflateSync(raw, { level: 1 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

const dir = path.join(__dirname, '..', 'icons');
fs.mkdirSync(dir, { recursive: true });
for (const size of [16, 48, 128]) {
  fs.writeFileSync(path.join(dir, `icon${size}.png`), makePNG(size, 37, 99, 235));
  console.log(`Created icons/icon${size}.png`);
}
```

- [ ] **Step 4: Run the icon generator**

```bash
node chrome-extension/scripts/generate_icons.js
```

Expected output:
```
Created icons/icon16.png
Created icons/icon48.png
Created icons/icon128.png
```

- [ ] **Step 5: Create empty stub files**

```bash
echo "" > chrome-extension/background.js
echo "" > chrome-extension/lib/utils.js
echo "" > chrome-extension/content/gmail.js
echo "" > chrome-extension/content/zoho.js
echo "<!DOCTYPE html><html><body></body></html>" > chrome-extension/popup/popup.html
echo "" > chrome-extension/popup/popup.js
```

- [ ] **Step 6: Load the extension in Chrome and verify no errors**

1. Open `chrome://extensions`
2. Toggle **Developer mode** on (top right)
3. Click **Load unpacked** → select the `chrome-extension/` folder
4. Verify: extension appears in the list with the blue icon, status shows no errors
5. Click the extension icon in the toolbar — a blank popup opens (expected at this stage)

- [ ] **Step 7: Commit**

```bash
git add chrome-extension/
git commit -m "feat: scaffold Chrome extension with manifest and icons"
```

---

### Task 2: Utility library + unit tests

**Files:**
- Create: `chrome-extension/lib/utils.js`
- Create: `chrome-extension/tests/utils.test.js`

**Interfaces:**
- Produces:
  - `buildEml(fields)` — `fields: { fromName: string, fromAddress: string, subject: string, date: string, bodyText: string }` → `string` (RFC 822 EML)
  - `makeFingerprint(fromAddress, subject, date)` — `(string, string, string)` → `string` (alphanumeric, ≤40 chars)
  - `verdictToStyle(verdict)` — `string` → `{ bg: string, color: string, icon: string, label: string }`

- [ ] **Step 1: Write the failing tests first**

Create `chrome-extension/tests/utils.test.js`:

```js
// Minimal test runner — no framework needed
if (typeof require !== 'undefined') {
  global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
}
const { buildEml, makeFingerprint, verdictToStyle } = require('../lib/utils.js');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log('  ✓', name); passed++; }
  catch (e) { console.error('  ✗', name + ':', e.message); failed++; }
}
function eq(a, b) {
  if (a !== b) throw new Error(`Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}
function ok(cond, msg) {
  if (!cond) throw new Error(msg || 'Expected truthy');
}

console.log('\nbuildEml');
test('includes From with name', () => {
  ok(buildEml({ fromName: 'Alice', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('From: Alice <a@b.com>'));
});
test('uses address only when name is empty', () => {
  ok(buildEml({ fromName: '', fromAddress: 'x@y.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('From: x@y.com'));
});
test('includes Subject header', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'Urgent wire', date: 'D', bodyText: '' })
    .includes('Subject: Urgent wire'));
});
test('falls back to (no subject) when subject empty', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: '', date: 'D', bodyText: '' })
    .includes('Subject: (no subject)'));
});
test('body text appears after blank line', () => {
  const eml = buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: 'click here' });
  const parts = eml.split('\r\n\r\n');
  eq(parts[1], 'click here');
});
test('To header is analyst@mailtrace.local', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('To: analyst@mailtrace.local'));
});

console.log('\nmakeFingerprint');
test('returns non-empty alphanumeric string', () => {
  const fp = makeFingerprint('a@b.com', 'Subject', '2026-01-01');
  ok(fp.length > 0, 'should not be empty');
  ok(/^[a-zA-Z0-9]+$/.test(fp), 'should be alphanumeric');
});
test('is deterministic for same inputs', () => {
  eq(makeFingerprint('a@b.com', 'S', 'D'), makeFingerprint('a@b.com', 'S', 'D'));
});
test('differs for different subjects', () => {
  ok(makeFingerprint('a@b.com', 'S1', 'D') !== makeFingerprint('a@b.com', 'S2', 'D'));
});
test('max 40 chars', () => {
  ok(makeFingerprint('very-long-address@very-long-domain.co.uk', 'A very long subject line for this email', '2026').length <= 40);
});

console.log('\nverdictToStyle');
test('phishing → red bg, DC2626, ✕ icon', () => {
  const s = verdictToStyle('phishing');
  eq(s.bg, '#FEF2F2'); eq(s.color, '#DC2626'); eq(s.icon, '✕');
});
test('PHISHING (uppercase) → red', () => {
  eq(verdictToStyle('PHISHING').color, '#DC2626');
});
test('malware → red', () => { eq(verdictToStyle('malware').color, '#DC2626'); });
test('bec → red', () => { eq(verdictToStyle('bec').color, '#DC2626'); });
test('suspicious → amber, D97706, ⚠ icon', () => {
  const s = verdictToStyle('suspicious');
  eq(s.bg, '#FEF3C7'); eq(s.color, '#D97706'); eq(s.icon, '⚠');
});
test('indeterminate → amber', () => { eq(verdictToStyle('indeterminate').color, '#D97706'); });
test('benign → green, 16A34A, ✓ icon', () => {
  const s = verdictToStyle('benign');
  eq(s.bg, '#F0FDF4'); eq(s.color, '#16A34A'); eq(s.icon, '✓');
});
test('clean → green', () => { eq(verdictToStyle('clean').color, '#16A34A'); });
test('likely_benign → green', () => { eq(verdictToStyle('likely_benign').color, '#16A34A'); });
test('unknown verdict → grey', () => { eq(verdictToStyle('').color, '#64748B'); });
test('label is uppercase of verdict', () => { eq(verdictToStyle('phishing').label, 'PHISHING'); });

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
```

- [ ] **Step 2: Run — verify all tests fail with "Cannot find module"**

```bash
node chrome-extension/tests/utils.test.js
```

Expected: `Error: Cannot find module '../lib/utils.js'` (or similar — utils.js is empty)

- [ ] **Step 3: Write `chrome-extension/lib/utils.js`**

```js
function buildEml({ fromName, fromAddress, subject, date, bodyText }) {
  const from = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  return [
    `From: ${from}`,
    `To: analyst@mailtrace.local`,
    `Subject: ${subject || '(no subject)'}`,
    `Date: ${date || new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    bodyText || ''
  ].join('\r\n');
}

function makeFingerprint(fromAddress, subject, date) {
  const raw = `${fromAddress}|${subject}|${date}`;
  const encoded = typeof btoa !== 'undefined'
    ? btoa(unescape(encodeURIComponent(raw)))
    : Buffer.from(raw).toString('base64');
  return encoded.replace(/[^a-zA-Z0-9]/g, '').slice(0, 40);
}

function verdictToStyle(verdict) {
  const v = (verdict || '').toLowerCase();
  if (['phishing', 'malware', 'bec'].includes(v))
    return { bg: '#FEF2F2', color: '#DC2626', icon: '✕', label: v.toUpperCase() };
  if (['suspicious', 'indeterminate'].includes(v))
    return { bg: '#FEF3C7', color: '#D97706', icon: '⚠', label: v.toUpperCase() };
  if (['clean', 'benign', 'likely_benign'].includes(v))
    return { bg: '#F0FDF4', color: '#16A34A', icon: '✓', label: v.toUpperCase() };
  return { bg: '#F1F5F9', color: '#64748B', icon: '?', label: (verdict || '').toUpperCase() || 'UNKNOWN' };
}

// Dual-mode: globals for extension, module exports for Node.js tests
if (typeof module !== 'undefined') module.exports = { buildEml, makeFingerprint, verdictToStyle };
```

- [ ] **Step 4: Run tests — verify all pass**

```bash
node chrome-extension/tests/utils.test.js
```

Expected: all 22 tests show `✓`, exit code 0

- [ ] **Step 5: Commit**

```bash
git add chrome-extension/lib/utils.js chrome-extension/tests/utils.test.js
git commit -m "feat: add utility library with buildEml, makeFingerprint, verdictToStyle"
```

---

### Task 3: Background service worker

**Files:**
- Modify: `chrome-extension/background.js`

**Interfaces:**
- Consumes: `buildEml` from `./lib/utils.js` (via `importScripts`)
- Consumes: `chrome.storage.session`, `chrome.runtime.onMessage`, `fetch`
- Message in: `{ action: 'analyze', fields: { fromName, fromAddress, subject, date, bodyText }, fingerprint: string }`
- Message out: `{ verdict, risk_score, confidence, case_number }` on success OR `{ error: string }` on failure

- [ ] **Step 1: Write `chrome-extension/background.js`**

```js
importScripts('./lib/utils.js');

const BACKEND        = 'http://localhost:8000';
const POLL_INTERVAL  = 500;
const POLL_MAX       = 60;

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action !== 'analyze') return false;
  handleAnalyze(msg.fields, msg.fingerprint).then(sendResponse);
  return true; // keep message channel open for async response
});

async function handleAnalyze(fields, fingerprint) {
  const cacheKey = 'mt_' + fingerprint;

  // Return cached result if available
  try {
    const hit = (await chrome.storage.session.get(cacheKey))[cacheKey];
    if (hit) return hit;
  } catch (_) {}

  try {
    // Build and submit the EML
    const eml  = buildEml(fields);
    const blob = new Blob([eml], { type: 'message/rfc822' });
    const form = new FormData();
    form.append('file', blob, 'email.eml');
    form.append('anchor', 'true');

    const ingestResp = await fetch(`${BACKEND}/api/ingest`, { method: 'POST', body: form });
    if (!ingestResp.ok) throw new Error(`ingest HTTP ${ingestResp.status}`);

    const ingestData  = await ingestResp.json();
    const caseNumber  = ingestData?.cases?.[0]?.case_number
                     ?? ingestData?.case?.case_number
                     ?? ingestData?.id;
    if (!caseNumber) throw new Error('no case number in response');

    // Poll until analysis completes
    for (let i = 0; i < POLL_MAX; i++) {
      await new Promise(r => setTimeout(r, POLL_INTERVAL));
      let caseData;
      try {
        const caseResp = await fetch(`${BACKEND}/api/cases/${caseNumber}`);
        if (!caseResp.ok) continue;
        caseData = await caseResp.json();
      } catch (_) { continue; }

      const status = caseData?.case?.status ?? caseData?.summary?.status;
      if (status && status !== 'analyzing' && status !== 'queued') {
        const result = {
          verdict:     caseData?.case?.verdict?.label    ?? caseData?.summary?.verdict    ?? 'indeterminate',
          risk_score:  caseData?.case?.verdict?.risk_score ?? caseData?.summary?.risk_score ?? 0,
          confidence:  caseData?.case?.verdict?.confidence ?? 0,
          case_number: caseNumber
        };
        try { await chrome.storage.session.set({ [cacheKey]: result }); } catch (_) {}
        return result;
      }
    }
    return { error: 'timeout' };

  } catch (err) {
    return { error: err.message };
  }
}
```

- [ ] **Step 2: Reload the extension in Chrome**

1. Go to `chrome://extensions`
2. Find "MailTrace Threat Scanner" → click the **reload** (↺) button
3. Click "Service Worker" link next to the extension
4. Verify the DevTools console for the service worker shows no errors on load

- [ ] **Step 3: Smoke-test the background worker via the DevTools console**

In the service worker DevTools console, run:

```js
// Should return a result object (backend must be running on localhost:8000)
chrome.runtime.sendMessage(
  { action: 'analyze',
    fingerprint: 'testfp123',
    fields: {
      fromName: 'Test', fromAddress: 'phishing@evil.com',
      subject: 'Urgent payment', date: new Date().toUTCString(),
      bodyText: 'Click here to verify your account http://evil.com'
    }
  },
  r => console.log('result:', JSON.stringify(r))
);
```

Expected: after ~3–10s, logs `result: {"verdict":"phishing","risk_score":...,"case_number":"MT-..."}`.  
If backend is offline: logs `result: {"error":"Failed to fetch"}` — expected and handled.

- [ ] **Step 4: Commit**

```bash
git add chrome-extension/background.js
git commit -m "feat: add background service worker with ingest, polling, and session cache"
```

---

### Task 4: Gmail content script

**Files:**
- Modify: `chrome-extension/content/gmail.js`

**Interfaces:**
- Consumes: `chrome.runtime.sendMessage` → background.js `handleAnalyze`
- DOM reads: `.a3s.aiL` (body), `.cf[email]` (from), `.hP` (subject), `.g3` (date), `.gmail_quote` (quoted replies to strip)
- DOM writes: injects `[data-mailtrace-banner]` Shadow DOM host before the email body

- [ ] **Step 1: Write `chrome-extension/content/gmail.js`**

```js
// ── Utilities (inlined — content scripts cannot use importScripts) ──────────

function buildEml({ fromName, fromAddress, subject, date, bodyText }) {
  const from = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  return [
    `From: ${from}`,
    `To: analyst@mailtrace.local`,
    `Subject: ${subject || '(no subject)'}`,
    `Date: ${date || new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    bodyText || ''
  ].join('\r\n');
}

function makeFingerprint(fromAddress, subject, date) {
  const raw     = `${fromAddress}|${subject}|${date}`;
  const encoded = btoa(unescape(encodeURIComponent(raw)));
  return encoded.replace(/[^a-zA-Z0-9]/g, '').slice(0, 40);
}

function verdictToStyle(verdict) {
  const v = (verdict || '').toLowerCase();
  if (['phishing', 'malware', 'bec'].includes(v))
    return { bg: '#FEF2F2', color: '#DC2626', icon: '✕', label: v.toUpperCase() };
  if (['suspicious', 'indeterminate'].includes(v))
    return { bg: '#FEF3C7', color: '#D97706', icon: '⚠', label: v.toUpperCase() };
  if (['clean', 'benign', 'likely_benign'].includes(v))
    return { bg: '#F0FDF4', color: '#16A34A', icon: '✓', label: v.toUpperCase() };
  return { bg: '#F1F5F9', color: '#64748B', icon: '?', label: (verdict || 'UNKNOWN').toUpperCase() };
}

// ── Banner injection via Shadow DOM ─────────────────────────────────────────

function removeBanner(container) {
  container.querySelector('[data-mailtrace-banner]')?.remove();
}

function injectBanner(container, state, data) {
  removeBanner(container);

  const host   = document.createElement('div');
  host.setAttribute('data-mailtrace-banner', '1');
  host.style.cssText = 'display:block;width:100%;margin-bottom:8px;';

  const shadow  = host.attachShadow({ mode: 'closed' });
  const wrapper = document.createElement('div');

  if (state === 'loading') {
    wrapper.style.cssText = `
      display:flex;align-items:center;gap:8px;padding:8px 14px;
      background:#F1F5F9;border:1px solid #CBD5E1;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:#64748B;`;
    wrapper.innerHTML = `
      <span style="width:12px;height:12px;border:2px solid #94A3B8;border-top-color:#2563EB;
        border-radius:50%;display:inline-block;animation:spin .8s linear infinite;"></span>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
      <span>MailTrace: Analyzing…</span>`;

  } else if (state === 'result') {
    const st    = verdictToStyle(data.verdict);
    const score = data.risk_score != null ? Math.round(data.risk_score) : '—';
    const conf  = data.confidence != null ? Math.round(data.confidence) : '—';
    wrapper.style.cssText = `
      display:flex;align-items:center;gap:10px;padding:8px 14px;
      background:${st.bg};border:1px solid ${st.color}44;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:${st.color};`;
    wrapper.innerHTML = `
      <b>${st.icon} ${st.label}</b>
      <span style="color:#64748B">Risk: <b style="color:${st.color}">${score}/100</b></span>
      <span style="color:#64748B">Confidence: <b>${conf}%</b></span>
      <a href="http://localhost:5173" target="_blank"
         style="margin-left:auto;color:${st.color};font-weight:700;text-decoration:none;
                padding:2px 8px;border:1px solid ${st.color}88;border-radius:4px;font-size:12px;">
        View in MailTrace →
      </a>`;

  } else { // error
    wrapper.style.cssText = `
      padding:8px 14px;background:#F1F5F9;border:1px solid #CBD5E1;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:#64748B;`;
    wrapper.textContent = `MailTrace: ${(data && data.message) || 'Analysis failed — open MailTrace to check manually'}`;
  }

  shadow.appendChild(wrapper);
  container.insertBefore(host, container.firstChild);
}

// ── Gmail DOM extraction ────────────────────────────────────────────────────

function extractFields(bodyEl) {
  const wrap = bodyEl.closest('[data-message-id]') || bodyEl.closest('.adn') || bodyEl.parentElement;

  const fromEl      = wrap.querySelector('.cf[email]') || wrap.querySelector('.gD[email]');
  const fromAddress = fromEl ? (fromEl.getAttribute('email') || '') : '';
  const fromName    = fromEl ? fromEl.textContent.trim() : '';

  const subjectEl = document.querySelector('.hP');
  const subject   = subjectEl ? subjectEl.textContent.trim() : '';

  const dateEl = wrap.querySelector('.g3') || wrap.querySelector('[data-tooltip]');
  const date   = dateEl
    ? (dateEl.getAttribute('title') || dateEl.getAttribute('data-tooltip') || dateEl.textContent.trim())
    : new Date().toUTCString();

  // Strip quoted replies before extracting body text
  const clone = bodyEl.cloneNode(true);
  clone.querySelectorAll('.gmail_quote').forEach(el => el.remove());
  const bodyText = clone.innerText || clone.textContent || '';

  return { fromName, fromAddress, subject, date, bodyText };
}

// ── Main observer ───────────────────────────────────────────────────────────

const processed = new WeakSet();

function handleBodyEl(bodyEl) {
  if (processed.has(bodyEl)) return;
  processed.add(bodyEl);

  const fields = extractFields(bodyEl);
  // Skip if this looks like a compose window or has no useful data
  if (!fields.fromAddress && !fields.subject) return;

  const container   = bodyEl.parentElement;
  const fingerprint = makeFingerprint(fields.fromAddress, fields.subject, fields.date);

  injectBanner(container, 'loading');

  chrome.runtime.sendMessage({ action: 'analyze', fields, fingerprint }, (result) => {
    if (chrome.runtime.lastError) {
      injectBanner(container, 'error', { message: 'Extension error — try reloading' });
      return;
    }
    if (!result || result.error) {
      const msg = result?.error === 'timeout'
        ? 'Analysis timed out — open MailTrace to check manually'
        : (result?.error || '').toLowerCase().includes('fetch')
          ? 'Backend offline (localhost:8000)'
          : 'Analysis failed — open MailTrace to check manually';
      injectBanner(container, 'error', { message: msg });
      return;
    }
    injectBanner(container, 'result', result);
  });
}

// Scan existing nodes on script load, then watch for new ones
document.querySelectorAll('.a3s.aiL').forEach(handleBodyEl);

new MutationObserver(() => {
  document.querySelectorAll('.a3s.aiL').forEach(el => {
    if (!processed.has(el)) handleBodyEl(el);
  });
}).observe(document.body, { childList: true, subtree: true });
```

- [ ] **Step 2: Reload the extension**

Go to `chrome://extensions` → reload MailTrace Threat Scanner.

- [ ] **Step 3: Manual test — open Gmail and verify banner appears**

1. Open `https://mail.google.com` in Chrome
2. Click any email to open it
3. Verify: a grey "MailTrace: Analyzing…" spinner appears at the top of the email body
4. After 3–15 seconds (backend analyzing): verify the spinner is replaced by a colored banner showing the verdict, risk score, confidence, and "View in MailTrace →" link
5. Click a second email — verify the banner updates for the new email
6. Click "View in MailTrace →" — verify `http://localhost:5173` opens in a new tab

If backend is not running: verify the banner shows "Backend offline (localhost:8000)".

- [ ] **Step 4: Commit**

```bash
git add chrome-extension/content/gmail.js
git commit -m "feat: add Gmail content script with MutationObserver, EML extraction, and Shadow DOM banner"
```

---

### Task 5: Zoho Mail content script

**Files:**
- Modify: `chrome-extension/content/zoho.js`

**Interfaces:**
- Consumes: `chrome.runtime.sendMessage` → background.js `handleAnalyze`
- DOM reads: `.mail-read-pane` or `#readPane` (container), `.zmail-from .addr-text[title]` (from), `.mail-subject-name` (subject), `.mail-date-time[title]` (date), `.mail-body-content` (body)
- DOM writes: same `[data-mailtrace-banner]` Shadow DOM banner as gmail.js
- Event: `hashchange` for email navigation detection

- [ ] **Step 1: Write `chrome-extension/content/zoho.js`**

```js
// ── Utilities (identical to gmail.js — inlined per-content-script) ──────────

function buildEml({ fromName, fromAddress, subject, date, bodyText }) {
  const from = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  return [
    `From: ${from}`,
    `To: analyst@mailtrace.local`,
    `Subject: ${subject || '(no subject)'}`,
    `Date: ${date || new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    bodyText || ''
  ].join('\r\n');
}

function makeFingerprint(fromAddress, subject, date) {
  const raw     = `${fromAddress}|${subject}|${date}`;
  const encoded = btoa(unescape(encodeURIComponent(raw)));
  return encoded.replace(/[^a-zA-Z0-9]/g, '').slice(0, 40);
}

function verdictToStyle(verdict) {
  const v = (verdict || '').toLowerCase();
  if (['phishing', 'malware', 'bec'].includes(v))
    return { bg: '#FEF2F2', color: '#DC2626', icon: '✕', label: v.toUpperCase() };
  if (['suspicious', 'indeterminate'].includes(v))
    return { bg: '#FEF3C7', color: '#D97706', icon: '⚠', label: v.toUpperCase() };
  if (['clean', 'benign', 'likely_benign'].includes(v))
    return { bg: '#F0FDF4', color: '#16A34A', icon: '✓', label: v.toUpperCase() };
  return { bg: '#F1F5F9', color: '#64748B', icon: '?', label: (verdict || 'UNKNOWN').toUpperCase() };
}

// ── Banner injection (identical logic to gmail.js) ───────────────────────────

function removeBanner(container) {
  container.querySelector('[data-mailtrace-banner]')?.remove();
}

function injectBanner(container, state, data) {
  removeBanner(container);
  const host = document.createElement('div');
  host.setAttribute('data-mailtrace-banner', '1');
  host.style.cssText = 'display:block;width:100%;margin-bottom:8px;';
  const shadow  = host.attachShadow({ mode: 'closed' });
  const wrapper = document.createElement('div');

  if (state === 'loading') {
    wrapper.style.cssText = `
      display:flex;align-items:center;gap:8px;padding:8px 14px;
      background:#F1F5F9;border:1px solid #CBD5E1;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:#64748B;`;
    wrapper.innerHTML = `
      <span style="width:12px;height:12px;border:2px solid #94A3B8;border-top-color:#2563EB;
        border-radius:50%;display:inline-block;animation:spin .8s linear infinite;"></span>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
      <span>MailTrace: Analyzing…</span>`;

  } else if (state === 'result') {
    const st    = verdictToStyle(data.verdict);
    const score = data.risk_score != null ? Math.round(data.risk_score) : '—';
    const conf  = data.confidence != null ? Math.round(data.confidence) : '—';
    wrapper.style.cssText = `
      display:flex;align-items:center;gap:10px;padding:8px 14px;
      background:${st.bg};border:1px solid ${st.color}44;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:${st.color};`;
    wrapper.innerHTML = `
      <b>${st.icon} ${st.label}</b>
      <span style="color:#64748B">Risk: <b style="color:${st.color}">${score}/100</b></span>
      <span style="color:#64748B">Confidence: <b>${conf}%</b></span>
      <a href="http://localhost:5173" target="_blank"
         style="margin-left:auto;color:${st.color};font-weight:700;text-decoration:none;
                padding:2px 8px;border:1px solid ${st.color}88;border-radius:4px;font-size:12px;">
        View in MailTrace →
      </a>`;

  } else {
    wrapper.style.cssText = `
      padding:8px 14px;background:#F1F5F9;border:1px solid #CBD5E1;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:#64748B;`;
    wrapper.textContent = `MailTrace: ${(data && data.message) || 'Analysis failed — open MailTrace to check manually'}`;
  }

  shadow.appendChild(wrapper);
  container.insertBefore(host, container.firstChild);
}

// ── Zoho Mail DOM extraction ─────────────────────────────────────────────────

function extractFields(pane) {
  const fromEl      = pane.querySelector('.zmail-from .addr-text') || pane.querySelector('.fromAddress span');
  const fromAddress = fromEl ? (fromEl.getAttribute('title') || fromEl.textContent.trim()) : '';
  const fromNameEl  = pane.querySelector('.zmail-from .fromName');
  const fromName    = fromNameEl ? fromNameEl.textContent.trim() : '';

  const subjectEl = pane.querySelector('.mail-subject-name') || pane.querySelector('.subject-text');
  const subject   = subjectEl ? subjectEl.textContent.trim() : '';

  const dateEl = pane.querySelector('.mail-date-time');
  const date   = dateEl ? (dateEl.getAttribute('title') || dateEl.textContent.trim()) : new Date().toUTCString();

  const bodyEl  = pane.querySelector('.mail-body-content') || pane.querySelector('#mailbody');
  const bodyText = bodyEl ? (bodyEl.innerText || bodyEl.textContent || '') : '';

  return { fromName, fromAddress, subject, date, bodyText };
}

// ── Main logic ───────────────────────────────────────────────────────────────

function getPane() {
  return document.querySelector('.mail-read-pane') || document.querySelector('#readPane');
}

function maybeProcess() {
  const pane = getPane();
  if (!pane || pane.children.length === 0) return;

  const fields = extractFields(pane);
  if (!fields.fromAddress && !fields.subject) return;

  const fingerprint = makeFingerprint(fields.fromAddress, fields.subject, fields.date);
  if (pane.dataset.mtLast === fingerprint) return; // same email still open
  pane.dataset.mtLast = fingerprint;

  injectBanner(pane, 'loading');

  chrome.runtime.sendMessage({ action: 'analyze', fields, fingerprint }, (result) => {
    if (chrome.runtime.lastError) {
      injectBanner(pane, 'error', { message: 'Extension error — try reloading' });
      return;
    }
    if (!result || result.error) {
      const msg = result?.error === 'timeout'
        ? 'Analysis timed out — open MailTrace to check manually'
        : (result?.error || '').toLowerCase().includes('fetch')
          ? 'Backend offline (localhost:8000)'
          : 'Analysis failed — open MailTrace to check manually';
      injectBanner(pane, 'error', { message: msg });
      return;
    }
    injectBanner(pane, 'result', result);
  });
}

// Run on hash navigation (Zoho uses hash routing)
window.addEventListener('hashchange', () => {
  const pane = getPane();
  if (pane) delete pane.dataset.mtLast; // allow reprocessing
  setTimeout(maybeProcess, 300); // give Zoho time to render new email
});

// Run on DOM mutations
new MutationObserver(maybeProcess).observe(document.body, { childList: true, subtree: true });

// Run immediately in case email already open
maybeProcess();
```

- [ ] **Step 2: Reload the extension**

Go to `chrome://extensions` → reload MailTrace Threat Scanner.

- [ ] **Step 3: Manual test — open Zoho Mail and verify banner appears**

1. Open `https://mail.zoho.com` (or `https://mail.zoho.in`) in Chrome
2. Click any email to open it in the reading pane
3. Verify: grey "MailTrace: Analyzing…" banner appears at the top of the reading pane
4. After analysis: verify colored verdict banner replaces the spinner
5. Navigate to a different email — verify banner updates for the new email
6. Verify navigating back to the first email does NOT re-submit (cache hit — result appears instantly)

- [ ] **Step 4: Commit**

```bash
git add chrome-extension/content/zoho.js
git commit -m "feat: add Zoho Mail content script with hashchange navigation support"
```

---

### Task 6: Toolbar popup

**Files:**
- Modify: `chrome-extension/popup/popup.html`
- Modify: `chrome-extension/popup/popup.js`

**Interfaces:**
- Consumes: `GET http://localhost:8000/api/health` (health check)
- Produces: 280px popup showing connection status, total analysis count, "Open MailTrace" button

- [ ] **Step 1: Write `chrome-extension/popup/popup.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MailTrace</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { width: 280px; font-family: system-ui, -apple-system, sans-serif;
           background: #0F172A; color: #F1F5F9; }
    .header { padding: 14px 16px 12px; border-bottom: 1px solid #1E293B;
              display: flex; align-items: center; gap: 8px; }
    .logo { font-size: 15px; font-weight: 800; letter-spacing: -0.02em; }
    .logo em { color: #2563EB; font-style: normal; }
    .status-row { padding: 12px 16px; display: flex; align-items: center;
                  gap: 8px; font-size: 13px; color: #CBD5E1; }
    .dot { width: 8px; height: 8px; border-radius: 50%;
           background: #475569; flex-shrink: 0; transition: background .2s; }
    .dot.green { background: #22C55E; }
    .dot.red   { background: #EF4444; }
    .stat { padding: 0 16px 12px; font-size: 12px; color: #64748B; }
    .open-btn { display: block; margin: 0 16px 14px; padding: 9px 0;
                background: #2563EB; color: #fff; text-align: center;
                border-radius: 6px; font-size: 13px; font-weight: 700;
                text-decoration: none; }
    .open-btn:hover { background: #1D4ED8; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">Mail<em>Trace</em></div>
  </div>
  <div class="status-row">
    <div class="dot" id="dot"></div>
    <span id="status-text">Checking&hellip;</span>
  </div>
  <div class="stat" id="count-text"></div>
  <a href="http://localhost:5173" target="_blank" class="open-btn">Open MailTrace &rarr;</a>
  <script src="popup.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write `chrome-extension/popup/popup.js`**

```js
const dot        = document.getElementById('dot');
const statusText = document.getElementById('status-text');
const countText  = document.getElementById('count-text');

async function checkBackend() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    const resp = await fetch('http://localhost:8000/api/health', { signal: ctrl.signal });
    clearTimeout(timer);
    if (!resp.ok) throw new Error('non-ok');
    const data = await resp.json();
    dot.className  = 'dot green';
    statusText.textContent = 'Connected to MailTrace backend';
    const total = data?.counts?.total ?? 0;
    countText.textContent  = `${total} email${total === 1 ? '' : 's'} analyzed in backend`;
  } catch {
    clearTimeout(timer);
    dot.className  = 'dot red';
    statusText.textContent = 'Backend offline (localhost:8000)';
    countText.textContent  = 'Start the backend to enable scanning';
  }
}

checkBackend();
```

- [ ] **Step 3: Reload the extension**

Go to `chrome://extensions` → reload MailTrace Threat Scanner.

- [ ] **Step 4: Manual test — verify popup**

1. Click the MailTrace shield icon in the Chrome toolbar
2. **Backend running:** verify green dot, "Connected to MailTrace backend", email count from the live backend
3. Stop the backend (`Ctrl+C` in its terminal), click the icon again — verify red dot and "Backend offline" message
4. Restart the backend, click again — verify green dot returns
5. Click "Open MailTrace →" — verify `http://localhost:5173` opens in a new tab

- [ ] **Step 5: Commit**

```bash
git add chrome-extension/popup/popup.html chrome-extension/popup/popup.js
git commit -m "feat: add toolbar popup with backend health check and analysis count"
```

---

## Self-Review Against Spec

| Spec section | Covered by |
|---|---|
| Manifest V3, permissions, host_permissions | Task 1 — manifest.json |
| Background service worker: ingest, polling, cache | Task 3 — background.js |
| Gmail DOM selectors (.a3s.aiL, .cf[email], .hP, .g3) | Task 4 — gmail.js |
| Quoted reply stripping (.gmail_quote removal) | Task 4 — extractFields() |
| Zoho DOM selectors (.mail-read-pane, .addr-text, etc.) | Task 5 — zoho.js |
| Zoho hashchange navigation | Task 5 — hashchange listener |
| Shadow DOM banner injection | Tasks 4 & 5 — injectBanner() |
| All verdict color states (red/amber/green/grey) | Task 2 — verdictToStyle() |
| "View in MailTrace →" link to localhost:5173 | Tasks 4 & 5 — banner HTML |
| 30s timeout (500ms × 60 attempts) | Task 3 — POLL_MAX constant |
| Session cache with mt_ prefix | Task 3 — cacheKey format |
| Error states: timeout / backend offline / failed | Tasks 4 & 5 — sendMessage callback |
| Toolbar popup: health + count + open link | Task 6 — popup.html + popup.js |
| EML reconstruction (RFC 822 format) | Task 2 — buildEml() |
| Fingerprint: alphanumeric, ≤40 chars | Task 2 — makeFingerprint() |
| No build step, no bundler | All tasks — plain JS files |
| Dev-mode loading instructions | Task 1 step 6 |
