function buildEml({ fromName, fromAddress, subject, date, bodyText }) {
  const from = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  // Synthetic Message-ID prevents hdr.no_message_id (+0.90 logit penalty).
  // Synthetic Received prevents hdr.no_received (+1.30 logit penalty).
  // Without these, every extension-submitted email is inflated by ~2.2 logit
  // purely because it was submitted without full headers — not because it is
  // actually suspicious.
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
