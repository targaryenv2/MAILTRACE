importScripts('./lib/utils.js');

const BACKEND       = 'http://localhost:8000';
const POLL_INTERVAL = 500;
const POLL_MAX      = 60;

// ── Gmail OAuth helpers ──────────────────────────────────────────────────────

function getAuthToken(interactive) {
  return new Promise(resolve =>
    chrome.identity.getAuthToken({ interactive }, token => {
      if (chrome.runtime.lastError || !token) resolve(null);
      else resolve(token);
    })
  );
}

// Fetch the complete raw RFC 2822 email via the Gmail API.
// Returns a Blob (message/rfc822) on success, null on any failure.
// Uses interactive=false so it never pops up a consent dialog automatically;
// the user grants permission once via the popup "Connect Gmail" button.
async function fetchRawEmailViaApi(msgId) {
  if (!msgId) return null;
  try {
    const token = await getAuthToken(false);
    if (!token) return null;

    const resp = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msgId}?format=raw`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!resp.ok) return null;

    const data = await resp.json();
    if (!data.raw) return null;

    // base64url → Uint8Array → Blob
    const b64     = data.raw.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - b64.length % 4) % 4);
    const binary  = atob(b64 + padding);
    const bytes   = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Blob([bytes], { type: 'message/rfc822' });
  } catch (_) {
    return null;
  }
}

// ── Message handlers ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action === 'analyze') {
    handleAnalyze(msg.fields, msg.fingerprint).then(sendResponse);
    return true;
  }
  if (msg.action === 'authGmail') {
    // Triggered from popup — show Google consent dialog if needed.
    getAuthToken(true).then(token =>
      sendResponse({ ok: !!token })
    );
    return true;
  }
  if (msg.action === 'checkGmailAuth') {
    getAuthToken(false).then(token =>
      sendResponse({ authed: !!token })
    );
    return true;
  }
});

async function handleAnalyze(fields, fingerprint) {
  const cacheKey = 'mt_' + fingerprint;
  const frontendUrl = 'http://localhost:5173';

  try {
    const hit = (await chrome.storage.session.get(cacheKey))[cacheKey];
    if (hit) return hit;
  } catch (_) {}

  try {
    // Priority 1: Gmail API — full raw email including DKIM/SPF/DMARC headers.
    // Priority 2: ?view=raw scrape already done by content script.
    // Priority 3: synthetic EML built from DOM fields (header-stripped fallback).
    let blob;
    const apiBlob = fields.msgId ? await fetchRawEmailViaApi(fields.msgId) : null;
    if (apiBlob) {
      blob = apiBlob;
    } else {
      const eml = fields.rawEml || buildEml(fields);
      blob = new Blob([eml], { type: 'message/rfc822' });
    }

    const form = new FormData();
    form.append('file', blob, 'email.eml');
    form.append('anchor', 'true');

    const ingestResp = await fetch(`${BACKEND}/api/ingest`, { method: 'POST', body: form });
    if (!ingestResp.ok) throw new Error(`ingest HTTP ${ingestResp.status}`);

    const ingestData = await ingestResp.json();
    const caseNumber = ingestData?.cases?.[0]?.case_number
                    ?? ingestData?.case?.case_number
                    ?? ingestData?.id;
    if (!caseNumber) throw new Error('no case number in response');

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
          case_number: caseNumber,
          case_url:    caseNumber ? `${frontendUrl}/?case=${encodeURIComponent(caseNumber)}` : frontendUrl,
          full_headers: !!apiBlob,
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
