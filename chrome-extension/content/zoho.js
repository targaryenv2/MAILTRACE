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
  // Include location.hash so that different emails (different URL) always get
  // a different fingerprint even when DOM extraction returns identical values.
  const raw     = `${location.hash}|${fromAddress}|${subject}|${date}`;
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
    const caseUrl = data.case_url || 'http://localhost:5173';
    wrapper.style.cssText = `
      display:flex;align-items:center;gap:10px;padding:8px 14px;
      background:${st.bg};border:1px solid ${st.color}44;border-radius:6px;
      font:13px/1 system-ui,sans-serif;color:${st.color};`;
    wrapper.innerHTML = `
      <b>${st.icon} ${st.label}</b>
      <span style="color:#64748B">Risk: <b style="color:${st.color}">${score}/100</b></span>
      <span style="color:#64748B">Confidence: <b>${conf}%</b></span>
      <a href="${caseUrl}" target="_blank"
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

// ── Zoho Mail DOM extraction (broad selector coverage) ───────────────────────

// Returns the email reading pane element, trying many selectors across
// different Zoho Mail UI versions. Zoho has shipped several redesigns;
// attribute wildcards catch the broadest range.
function getPane() {
  // Prefer more-specific selectors first so we don't match a stable outer
  // container that is present even when no individual email is open.
  const selectors = [
    // ID-based (various Zoho Mail versions)
    '#readPaneComponent', '#readPane', '#zpreadPane',
    '[id*="readPane"]', '[id*="readpane"]',
    '[id*="mailDetail"]', '[id*="maildetail"]',
    '[id*="previewPane"]', '[id*="mailPreview"]',
    '[id*="zmailBody"]', '[id*="mailBody"]',
    // Class-based
    '.mail-read-pane', '.zm-read-pane', '.mailDetailView',
    '[class*="readPane"]', '[class*="readpane"]',
    '[class*="mailDetail"]', '[class*="previewPane"]',
    '[class*="mailBody"]',
    // Data-attribute patterns
    '[data-testid*="mail"]', '[data-id*="preview"]',
  ];
  for (const sel of selectors) {
    try {
      const el = document.querySelector(sel);
      if (!el || el.children.length === 0) continue;
      // Guard: the matched element must contain text that looks like an email
      // subject or sender — this prevents matching a stable layout shell that
      // is always present (even on the inbox list view with no email open).
      const text = el.innerText || el.textContent || '';
      if (text.trim().length > 20) return el;
    } catch (_) {}
  }
  return null;
}

function extractBodyText(pane) {
  // 1. Named body selectors
  const bodySelectors = [
    '.mail-body-content', '#mailbody', '.mailBody',
    '[class*="mailBody"]', '[class*="mail-body"]',
    '[class*="msgBody"]', '[class*="messageBody"]',
    '[id*="mailBody"]', '[id*="msgBody"]',
  ];
  for (const sel of bodySelectors) {
    try {
      const el = pane.querySelector(sel);
      if (el) return el.innerText || el.textContent || '';
    } catch (_) {}
  }
  // 2. Iframe fallback — Zoho sometimes renders body inside a same-origin iframe
  const iframe = pane.querySelector('iframe');
  if (iframe) {
    try {
      const doc = iframe.contentDocument || iframe.contentWindow?.document;
      if (doc && doc.body) return doc.body.innerText || doc.body.textContent || '';
    } catch (_) {} // cross-origin guard
  }
  return '';
}

function extractSubject(pane) {
  const selectors = [
    '.mail-subject-name', '.subject-text', '.mailSubject',
    '[class*="subject"]', '[class*="Subject"]',
    '[id*="subject"]', 'h1', 'h2',
  ];
  for (const sel of selectors) {
    try {
      const el = pane.querySelector(sel);
      const text = el?.textContent?.trim();
      if (text && text.length > 0 && text.length < 500) return text;
    } catch (_) {}
  }
  // Zoho Mail sets page title to "{Subject} - Zoho Mail" when viewing an email
  const title = document.title;
  if (title && (title.includes(' - Zoho Mail') || title.includes(' | Zoho Mail'))) {
    return title.replace(/ [-|] Zoho Mail.*$/, '').trim();
  }
  return '';
}

function extractFromAddress(pane) {
  const selectors = [
    '.zmail-from .addr-text', '.fromAddress span',
    '[class*="from"] [class*="addr"]',
    '[class*="from"] [class*="email"]',
    '[class*="sender"] [class*="email"]',
    '[class*="senderMail"]', '[class*="fromMail"]',
    '[class*="fromAddress"]', '[class*="senderAddress"]',
    // Elements that often carry the email in a title or data attribute
    '[class*="from"][title]', '[class*="sender"][title]',
  ];
  for (const sel of selectors) {
    try {
      const el = pane.querySelector(sel);
      if (!el) continue;
      // Prefer title/data attributes which hold the raw email address
      const addr = el.getAttribute('title') || el.getAttribute('data-email') || el.textContent.trim();
      if (addr && addr.includes('@')) return addr;
    } catch (_) {}
  }
  return '';
}

function extractFromName(pane) {
  const selectors = [
    '.zmail-from .fromName', '[class*="fromName"]',
    '[class*="senderName"]', '[class*="from"] [class*="name"]',
    '[class*="sender"] [class*="name"]',
  ];
  for (const sel of selectors) {
    try {
      const el = pane.querySelector(sel);
      const text = el?.textContent?.trim();
      if (text) return text;
    } catch (_) {}
  }
  return '';
}

function extractDate(pane) {
  const selectors = [
    '.mail-date-time', '[class*="mailDate"]', '[class*="date-time"]',
    '[class*="receivedDate"]', '[class*="sentDate"]',
    '[class*="mailTime"]', 'time', '[datetime]',
  ];
  for (const sel of selectors) {
    try {
      const el = pane.querySelector(sel);
      if (!el) continue;
      const val = el.getAttribute('title') || el.getAttribute('datetime') ||
                  el.getAttribute('data-tooltip') || el.textContent.trim();
      if (val) return val;
    } catch (_) {}
  }
  return new Date().toUTCString();
}

function extractFields(pane) {
  return {
    fromAddress: extractFromAddress(pane),
    fromName:    extractFromName(pane),
    subject:     extractSubject(pane),
    date:        extractDate(pane),
    bodyText:    extractBodyText(pane),
  };
}

// ── Main logic ───────────────────────────────────────────────────────────────

function maybeProcess() {
  const pane = getPane();
  if (!pane) return;

  const fields = extractFields(pane);
  // Require at least one of from or subject — skip compose/empty views
  if (!fields.fromAddress && !fields.subject) return;

  const fingerprint = makeFingerprint(fields.fromAddress, fields.subject, fields.date);
  if (pane.dataset.mtLast === fingerprint) return;
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

// ── Navigation detection ────────────────────────────────────────────────────
// All three routing methods Zoho uses must clear dedup so a freshly-opened
// email is not skipped because the pane element is reused between messages.

function onZohoNavigation() {
  const pane = getPane();
  if (pane) delete pane.dataset.mtLast;
  setTimeout(maybeProcess, 500);
}

// Hash-based routing (classic Zoho Mail)
window.addEventListener('hashchange', onZohoNavigation);

// Back/forward navigation
window.addEventListener('popstate', onZohoNavigation);

// History API mutations — Zoho newer UI uses both pushState AND replaceState
// when loading an email within the same view.
['pushState', 'replaceState'].forEach(method => {
  const orig = history[method].bind(history);
  history[method] = function (...args) {
    orig(...args);
    onZohoNavigation();
  };
});

// Watch for DOM mutations (email loaded into reading pane)
new MutationObserver(maybeProcess).observe(document.body, { childList: true, subtree: true });

// Run immediately in case email is already open
maybeProcess();
