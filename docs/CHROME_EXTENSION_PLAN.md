# MailTrace Chrome Extension Plan

## Goal

Create a Chrome Manifest V3 extension that warns Gmail users when an open email
looks like phishing, business-email compromise, spoofing, malware, or another
high-risk message. The extension will use MailTrace for analysis and will link
users to the existing case dashboard for evidence and response actions.

The first release is a **Gmail-only, user-consented browser scan**. It is not a
replacement for full forensic ingestion: Gmail's page does not reliably expose
the original MIME source, authentication headers, or attachments.

## Scope

### MVP

- Support Gmail in Chrome (`https://mail.google.com/*`).
- Let a user analyse the currently open email with a button in the message UI.
- Extract the visible sender, sender address (when available), subject, text,
  and URLs from Gmail's rendered message.
- Submit a normalized RFC 822-compatible message to MailTrace.
- Render an in-email verdict banner with risk level, short reasons, and a link
  to the resulting MailTrace case.
- Provide an explicit **Report to MailTrace** action for escalated analysis.
- Store only extension preferences locally: API base URL and scan preference.

### Explicitly deferred

- Outlook, Yahoo Mail, and other webmail providers.
- Automatic attachment extraction or upload.
- Blocking page navigation or deleting/quarantining email.
- Silent scanning of every inbox message.
- Full header / SPF / DKIM / DMARC inspection without an email-provider API.
- Gmail API OAuth and raw-message retrieval (phase 2).

## Architecture

```text
Gmail message view
       |
       | content script extracts visible data
       v
Extension service worker ---- settings / consent --> chrome.storage
       |
       | POST MailTrace API
       v
MailTrace ingestion and detection pipeline
       |
       | verdict, score, evidence, case ID
       v
Content script inserts warning banner and actions in Gmail
```

The extension should not call the API directly from Gmail's page. A content
script sends a message to the service worker, and the service worker makes the
network request. This keeps API configuration and request handling in one
place.

## Repository layout

Add a standalone extension workspace so it can be built and reviewed separately
from the React dashboard:

```text
extension/
  package.json
  tsconfig.json
  vite.config.ts
  public/
    manifest.json
    icons/
  src/
    content.ts             # Gmail observer and page integration
    gmail.ts               # DOM extraction and message identity helpers
    service-worker.ts      # API calls, cache, notifications
    api.ts                 # Typed MailTrace client
    ui.ts                  # Warning banner and action controls
    types.ts
    options.html
    options.ts
    options.css
  tests/
```

Use TypeScript and a Manifest V3-compatible build setup. Keep Gmail selectors
isolated in `gmail.ts`, because Gmail's DOM is frequently changed.

## Chrome permissions

Use the smallest practical permission set:

```json
{
  "manifest_version": 3,
  "permissions": ["storage", "notifications"],
  "host_permissions": [
    "https://mail.google.com/*",
    "https://api.example.com/*"
  ],
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }],
  "background": { "service_worker": "service-worker.js", "type": "module" },
  "options_page": "options.html"
}
```

During local development, allow `http://127.0.0.1:8000/*`; use only the
production HTTPS API host in the release build. Do not request broad history,
tabs, downloads, or `webRequest` permissions for the MVP.

## Backend integration

### MVP adapter

The existing `POST /api/ingest` endpoint accepts RFC 822 `.eml` uploads. The
extension can produce a minimal synthetic message containing only data that is
visible in Gmail:

```text
From: Sender Name <sender@example.com>
Subject: Verify your account
Date: ...
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Visible message text
```

Submit it using `multipart/form-data` with:

- `source=chrome_extension`
- `anchor=false` for normal scans
- a deterministic filename such as `gmail-visible-message.eml`

The returned case bundle supplies the verdict, risk score, signal titles, and
case reference required by the banner. The UI must call this a **visible-content
scan** so it does not imply header or attachment evidence was collected.

### Recommended dedicated endpoint

Before public rollout, add `POST /api/extension/analyze`. It should accept a
structured, versioned payload and avoid pretending the data is raw email:

```json
{
  "provider": "gmail",
  "capture_level": "rendered_content",
  "message_key": "non-sensitive dedupe hash",
  "sender": { "display_name": "", "address": "" },
  "subject": "",
  "body_text": "",
  "links": ["https://..."],
  "user_requested": true
}
```

The endpoint should normalize the payload internally, invoke the same MailTrace
pipeline, set `source="chrome_extension"`, and return a compact response. Add
CORS support only for the specific deployed extension ID and authenticated API
origins; do not use a permissive production wildcard.

## User experience

### Initial interaction

1. A small `Analyse with MailTrace` action appears only when an email is open.
2. Clicking it shows an analysing state in the same location.
3. A low-risk result shows a quiet green/neutral result and no browser alert.
4. A suspicious result displays a yellow banner.
5. A phishing, BEC, malware, or risk score of at least 65 displays a red warning
   banner and may send a Chrome notification if the user has enabled it.

### Warning content

Each banner includes:

- Verdict and confidence/risk level.
- No more than three plain-language reasons from actual MailTrace signals.
- `View full analysis`, opening the local or deployed dashboard case.
- `Report to MailTrace`, which requests a preserved/anchored case only after the
  user confirms.
- `Dismiss` and a non-persistent false-positive feedback action.

Never visually imitate Gmail system warnings. Render the component in a shadow
DOM root, use MailTrace branding, and include an accessible label.

## Privacy and security requirements

- Require clear onboarding consent before sending email content to MailTrace.
- Default to manual analysis. An optional "scan when opened" setting must be
  off by default.
- State exactly what is sent: visible sender, subject, body text, and URLs.
- Do not collect passwords, compose-window content, inbox lists, or credentials.
- Do not persist raw content in the extension; retain only preference values and
  short-lived request/result state.
- Use HTTPS, authenticated API requests, server-side rate limiting, payload-size
  limits, and an extension-specific API key/token strategy.
- Redact or mask email data in logs; follow the existing MailTrace privacy
  controls and retention policy.
- Keep normal extension scans unanchored. Anchoring is an explicit reporting
  action because it creates a durable forensic record.

## Implementation phases

### Phase 0 — contracts and UX (1–2 days)

- Define `ExtensionAnalysisRequest` and compact response types.
- Choose API authentication and CORS policy.
- Define risk thresholds and copy for benign, suspicious, and high-risk states.
- Create Gmail fixture HTML representing message variations.

### Phase 1 — extension foundation (2–3 days)

- Scaffold the TypeScript Manifest V3 project.
- Add options page for API URL, consent, and auto-scan preference.
- Add service worker message routing and typed API client.
- Load the unpacked extension in Chrome and verify settings persistence.

### Phase 2 — Gmail extraction and manual scan (3–5 days)

- Detect Gmail route/message changes with `MutationObserver`.
- Extract sender, subject, visible text, and link destination/text safely.
- Create stable per-view deduplication so a message is not repeatedly submitted.
- Add the manual analysis control, loading state, error handling, and banner.

### Phase 3 — MailTrace API support (2–4 days)

- Initially use `/api/ingest` with normalized `.eml` input.
- Implement and test `/api/extension/analyze` before public release.
- Set extension-specific source metadata, safe defaults, rate limits, and CORS.
- Return a compact verdict payload rather than the entire forensic case unless
  the user opens the dashboard.

### Phase 4 — reporting and notifications (2–3 days)

- Add the confirmed reporting/anchoring workflow.
- Open a selected case in the existing dashboard.
- Add opt-in notifications for high-confidence threats only.
- Add false-positive feedback without changing the current verdict silently.

### Phase 5 — provider API and forensic mode (future)

- Obtain Google OAuth verification requirements and implement Gmail API access.
- Fetch raw message source only after granular user authorization.
- Route raw source to the full MailTrace parser to enable authentication-header
  and MIME/attachment analysis.
- Add Outlook support through a provider-specific adapter, not Gmail selectors.

## Testing and acceptance criteria

### Automated tests

- Unit-test RFC 822 normalization and API payload construction.
- Unit-test Gmail extraction against saved DOM fixtures.
- Test selector failure, missing sender, malformed URL, message changes, timeout,
  and offline API errors.
- Test banner rendering, accessibility, and duplicate-scan suppression.
- Add backend tests for schema validation, CORS, authorization, and rate limits.

### Manual tests

- Load the unpacked extension in Chrome developer mode.
- Test Gmail desktop layouts, conversation threads, forwarded mail, plaintext,
  HTML mail, multiple links, and language variations.
- Verify no banner appears in Compose and no compose text is collected.
- Verify an email is not uploaded before a manual user action by default.
- Confirm high-risk sample emails display the correct MailTrace evidence and
  dashboard deep link.

### MVP completion checklist

- [ ] Manual Gmail scan works end-to-end against the local MailTrace backend.
- [ ] Users see a useful verdict banner derived from actual pipeline signals.
- [ ] The extension has no unnecessary Chrome permissions.
- [ ] Consent, privacy copy, error states, and opt-out are implemented.
- [ ] Cases are marked `chrome_extension` and ordinary scans are not anchored.
- [ ] Unit, backend, and manual acceptance tests pass.
- [ ] A production build uses HTTPS, scoped CORS, and authenticated API access.

## Delivery milestones

1. **Local demo:** unpacked Chrome extension + manual Gmail scan + local API.
2. **Internal pilot:** dedicated extension endpoint, consent, auth, telemetry, and
   fixture-based regression testing.
3. **Public beta:** hosted API, privacy policy, Chrome Web Store listing assets,
   security review, and support process.
4. **Forensic edition:** Gmail API raw-message integration and full MailTrace
   header/attachment analysis.
