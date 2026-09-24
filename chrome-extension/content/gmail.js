// ── Utilities (inlined — content scripts cannot use importScripts) ──────────

function buildEml({ fromName, fromAddress, subject, date, bodyText }) {
  const from  = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  const msgId = `<ext-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}@mailtrace.local>`;
  const rcvd  = `from extension (extension [127.0.0.1]) by mailtrace.local with SMTP id ext; ${date || new Date().toUTCString()}`;
  return [
    `From: ${from}`,
    `To: analyst@mailtrace.local`,
    `Subject: ${subject || '(no subject)'}`,
    `Date: ${date || new Date().toUTCString()}`,
    `Message-ID: ${msgId}`,
    `Received: ${rcvd}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    bodyText || ''
  ].join('\r\n');
}

// ── Raw email fetch ──────────────────────────────────────────────────────────
// Gmail's ?view=raw endpoint returns the complete original email including
// Received chain, DKIM-Signature, Authentication-Results, ARC-* headers —
// everything the synthetic EML lacks. The content script is same-origin with
// mail.google.com so the fetch is allowed without extra permissions.

function getGmailMessageId(wrap) {
  // Prefer the data-message-id attribute set by Gmail on the message container.
  const fromAttr = wrap && wrap.closest('[data-message-id]');
  if (fromAttr) return fromAttr.getAttribute('data-message-id');
  // Fall back to the hex ID in the URL hash (last segment wins for multi-message threads).
  const segs = location.hash.match(/[/#]([0-9A-Fa-f]{16,})/g) || [];
  if (segs.length) return segs[segs.length - 1].replace(/^[/#]/, '');
  return null;
}

async function fetchRawEmail(msgId) {
  if (!msgId) return null;
  try {
    const resp = await fetch(`/mail/u/0/?view=raw&th=${msgId}`, {
      credentials: 'same-origin',
    });
    if (!resp.ok) return null;
    const html = await resp.text();
    // Gmail wraps the raw email in a <pre> element.
    const m = html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
    if (!m) return null;
    return m[1]
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&#39;/g, "'")
      .replace(/&quot;/g, '"');
  } catch (_) {
    return null;
  }
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

async function handleBodyEl(bodyEl) {
  if (processed.has(bodyEl)) return;
  processed.add(bodyEl);

  const fields = extractFields(bodyEl);
  // Skip compose windows and empty panes
  if (!fields.fromAddress && !fields.subject) return;

  const container   = bodyEl.parentElement;
  const fingerprint = makeFingerprint(fields.fromAddress, fields.subject, fields.date);

  injectBanner(container, 'loading');

  // Attempt to fetch the full raw email. This gives the backend authentication
  // headers (DKIM, SPF, DMARC, Received chain) so the score matches what a
  // full-EML submission via the dashboard would produce.
  const wrap   = bodyEl.closest('[data-message-id]') || bodyEl.closest('.adn') || bodyEl.parentElement;
  const msgId  = getGmailMessageId(wrap);
  const rawEml = await fetchRawEmail(msgId);

  try {
    chrome.runtime.sendMessage(
      { action: 'analyze', fields: { ...fields, rawEml, msgId }, fingerprint },
      (result) => {
        if (chrome.runtime.lastError) {
          const errMsg = chrome.runtime.lastError.message || '';
          if (errMsg.includes('invalidated') || errMsg.includes('receiving end does not exist')) {
            injectBanner(container, 'error', { message: 'Extension reloaded — refresh the page' });
          } else {
            injectBanner(container, 'error', { message: 'Extension error — try reloading' });
          }
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
      }
    );
  } catch (err) {
    injectBanner(container, 'error', { message: 'Extension reloaded — refresh the page' });
  }
}

// Scan existing nodes on script load, then watch for new ones
document.querySelectorAll('.a3s.aiL').forEach(handleBodyEl);

new MutationObserver(() => {
  document.querySelectorAll('.a3s.aiL').forEach(el => {
    if (!processed.has(el)) handleBodyEl(el);
  });
}).observe(document.body, { childList: true, subtree: true });
