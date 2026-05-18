# Demo Script

This is the operator runbook for a 5-minute Triagent demo using the curated modern demo corpus.

## Goal

Show one clear story:

- Triagent turns messy reported emails into structured evidence.
- Analysts can inspect authentication, URLs, attachments, transmission, and message content without tool-hopping.
- Analysts stay in control of the final decision.
- Every decision can be exported and audited.

## Start The Demo

From the repo root:

```bash
make demo
```

This prepares the local stack, resets the curated demo corpus, and starts the app.

Default login:

- URL: `http://localhost:3000/login`
- Username: `admin`
- Password: `change-me`

Operator notes:

- Use `Uploads` at `/reports`, not `In-tray`.
- Click `Clear` in the search toolbar if any persisted filters are active.
- If the UI still looks stale after reset, hard refresh once.

## Dataset State

After `make demo`, the demo split contains seven uploads:

| Sample ID | Subject | What it demonstrates |
| --- | --- | --- |
| `m365_session_expiry_redirect_001` | `Action required: Microsoft 365 session expires today` | Credential harvest with redirect analysis |
| `vendor_invoice_attachment_001` | `Updated invoice and remittance details` | Attachment lure with hashes and evidence export |
| `compromised_vendor_portal_001` | `Q2 billing document requires review` | Auth passes, but business context and redirects still matter |
| `executive_wire_replyto_001` | `Can you handle this before 4?` | BEC-style reply-to mismatch without links |
| `teams_qr_login_lure_001` | `Teams mobile access expires tonight` | QR/login lure with inert image attachment |
| `benign_vendor_portal_notice_001` | `May supplier portal maintenance window` | Benign external control |
| `benign_internal_it_notice_001` | `Planned VPN maintenance on Saturday` | Benign internal control |

By default, the most demo-friendly open cases are:

- `m365_session_expiry_redirect_001`
- `vendor_invoice_attachment_001`
- `benign_vendor_portal_notice_001`

The remaining cases are useful for resolved-case review, audit history, and broader workflow discussion.

## 5-Minute Flow

Use this report order:

1. `m365_session_expiry_redirect_001` - `Action required: Microsoft 365 session expires today`
2. `vendor_invoice_attachment_001` - `Updated invoice and remittance details`
3. `benign_vendor_portal_notice_001` - `May supplier portal maintenance window`
4. `compromised_vendor_portal_001` - `Q2 billing document requires review`
5. `executive_wire_replyto_001` - `Can you handle this before 4?`

### 0:00-0:30 Reset And Login

1. Run `make demo`.
2. Open `http://localhost:3000/login`.
3. Sign in with `admin / change-me`.
4. Open `Uploads`.

Talk track:

`This is a deterministic local demo. I can reset the product to the same known phishing-triage dataset before every walkthrough.`

### 0:30-1:00 Show The Queue

1. Confirm the upload list is sorted newest-first.
2. Point out the mix of open and resolved cases.
3. Explain that this is an analyst workspace, not a black-box auto-close tool.

Talk track:

`The goal is to reduce the repetitive parsing work. The analyst still owns the final verdict, but the evidence is already organized.`

### 1:00-2:00 Resolve The Credential-Harvest Case

Open `Action required: Microsoft 365 session expires today`.

Click path:

1. Go to `URLs`.
2. Show the original URL/domain and the resolved destination.
3. Go to `Authentication`.
4. Point out failed authentication and the sender alignment problem.
5. Click `Resolve`.
6. Review the `Analyst Verdict Draft`.
7. Keep `Disposition` as `Malicious`.
8. Set `Classification code` to `CRED_HARV`.
9. Review the preselected flagged artifacts.
10. Click `Resolve`.

Talk track:

`This is the happy-path phishing case. Triagent keeps the original message, extracts the suspicious URL evidence, gives the analyst a draft conclusion, and preserves the resolution trail.`

### 2:00-2:45 Show The Attachment Case

Open `Updated invoice and remittance details`.

Click path:

1. Go to `Attachments`.
2. Show the inert ZIP attachment.
3. Point out MD5, SHA-1, and SHA-256.
4. Open the attachment actions menu.
5. Show that file name and hashes can be flagged.
6. Use the report actions menu to show evidence export options.

Talk track:

`Attachment handling is deliberately evidence-first: file metadata, hashes, analyst flags, and exportable artifacts. Triagent does not need to upload attachments to a cloud service to make the case reviewable.`

### 2:45-3:15 Show A Benign Control

Open `May supplier portal maintenance window`.

Click path:

1. Go to `Details`.
2. Show normal sender and recipient metadata.
3. Go to `Authentication`.
4. Show SPF, DKIM, and DMARC passing.
5. Go to `URLs`.
6. Show the stable vendor portal URL.

Talk track:

`Not every reported email is malicious. The tool should make benign resolution just as defensible as malicious resolution.`

### 3:15-4:15 Show A Subtle Business-Context Case

Open `Q2 billing document requires review`.

Click path:

1. Go to `Authentication`.
2. Point out that SPF, DKIM, and DMARC pass.
3. Go to `URLs`.
4. Show that the case still deserves review because the business context and redirect destination matter.
5. Open the rendered email body.

Talk track:

`This is why Triagent is not just an authentication dashboard. Authentication can pass on compromised or abused infrastructure. Analysts need the full evidence context.`

### 4:15-4:45 Show A BEC-Style Case

Open `Can you handle this before 4?`.

Click path:

1. Go to `Details`.
2. Compare `From` and `Reply-To`.
3. Mention that no URL or attachment is required for a case to be suspicious.

Talk track:

`This is the email-security version of paperwork reduction. The interesting signal is not a payload; it is the mismatch and the requested action.`

### 4:45-5:00 Close On Auditability And Deployment

Return to `Uploads` or stay on the current report.

Close with:

- `Analyst-in-the-loop resolution`
- `Evidence export and IOC export`
- `Audit log on every resolution`
- `Original uploaded message preserved`
- `Compose-based local deployment today, on-prem direction by design`

Suggested closing line:

`The product thesis is not full autonomy. It is faster, evidence-backed phishing decisions with a clear audit trail and a deployment model that fits sensitive environments.`

## Backup Order If Time Gets Tight

If you only have 3 minutes:

1. Queue overview in `Uploads`
2. `Action required: Microsoft 365 session expires today`
3. `Updated invoice and remittance details`
4. End on `Audit log` + `PDF` + `IOC CSV`

## Common Failure Recovery

If the dataset is wrong:

```bash
make demo-reset
```

If old queue filters are still applied:

- Click `Clear` in the search toolbar.

If you only want to reset data without starting the app:

```bash
make demo-reset
```

If you need the broader regression set instead of the curated demo:

```bash
make import-synthetic SPLIT=gold
```
