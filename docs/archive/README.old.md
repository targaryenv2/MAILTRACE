# MailTrace demo dataset

These four `.eml` files are sanitized, synthetic fixtures for offline demos and smoke tests. They contain reserved `.test` domains and documentation IP space; they do not represent real people, organizations, or infrastructure.

| Fixture | Expected path |
| --- | --- |
| `01-phishing-password-expiry.eml` | spoofing, auth failure, urgency, suspicious URL |
| `02-bec-wire-transfer.eml` | reply-to divergence, financial BEC language |
| `03-dangerous-attachment.eml` | multipart parsing, base64 attachment hashing, dangerous extension |
| `04-legitimate-notice.eml` | authenticated, low-risk baseline |

Use the ingest screen to upload a fixture. Do not use synthetic fixtures as a machine-learning training set; they are demonstration inputs only.
