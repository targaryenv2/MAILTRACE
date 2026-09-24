const dot          = document.getElementById('dot');
const statusText   = document.getElementById('status-text');
const countText    = document.getElementById('count-text');
const gmailDot     = document.getElementById('gmail-dot');
const gmailStatus  = document.getElementById('gmail-status-text');
const gmailHint    = document.getElementById('gmail-hint');
const connectBtn   = document.getElementById('connect-btn');

// ── Backend health ────────────────────────────────────────────────────────────

async function checkBackend() {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    const resp = await fetch('http://localhost:8000/api/health', { signal: ctrl.signal });
    clearTimeout(timer);
    if (!resp.ok) throw new Error('non-ok');
    const data = await resp.json();
    dot.className       = 'dot green';
    statusText.textContent = 'Connected to MailTrace backend';
    const total = data?.counts?.total ?? 0;
    countText.textContent  = `${total} email${total === 1 ? '' : 's'} analyzed`;
  } catch {
    clearTimeout(timer);
    dot.className       = 'dot red';
    statusText.textContent = 'Backend offline (localhost:8000)';
    countText.textContent  = 'Start the backend to enable scanning';
  }
}

// ── Gmail API auth status ─────────────────────────────────────────────────────

function setGmailAuthed() {
  gmailDot.className     = 'dot green';
  gmailStatus.textContent = 'Full-header analysis active';
  gmailHint.textContent   = 'Extension uses Gmail API for exact analysis';
  connectBtn.textContent  = 'Connected';
  connectBtn.disabled     = true;
}

function setGmailUnauthed() {
  gmailDot.className     = 'dot yellow';
  gmailStatus.textContent = 'Not connected';
  gmailHint.textContent   = 'Connect to enable full-header analysis (same accuracy as dashboard)';
  connectBtn.textContent  = 'Connect Gmail';
  connectBtn.disabled     = false;
}

async function checkGmailAuth() {
  chrome.runtime.sendMessage({ action: 'checkGmailAuth' }, resp => {
    if (chrome.runtime.lastError || !resp) return;
    if (resp.authed) setGmailAuthed(); else setGmailUnauthed();
  });
}

connectBtn.addEventListener('click', () => {
  connectBtn.disabled     = true;
  connectBtn.textContent  = 'Connecting…';
  chrome.runtime.sendMessage({ action: 'authGmail' }, resp => {
    if (chrome.runtime.lastError || !resp?.ok) {
      connectBtn.disabled    = false;
      connectBtn.textContent = 'Connect Gmail';
      gmailStatus.textContent = 'Authorization failed — try again';
    } else {
      setGmailAuthed();
    }
  });
});

checkBackend();
checkGmailAuth();
