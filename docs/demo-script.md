# Demo Script

This is the operator runbook for a 5-minute Triagent demo using the curated `demo` split.

## Goal

Show one clear story:

- Triagent separates obvious phishing from routine mail
- analysts can inspect evidence quickly without tool-hopping
- analysts stay in control of the final decision
- every decision can be exported and audited

## Pre-Demo Reset

From the repo root:

```bash
make demo-reset
```

This loads the curated `demo` split in a mixed state.

Default login:

- URL: `http://localhost:3000/login`
- Username: `admin`
- Password: `change-me`

Operator notes:

- Use `Uploads` at `/reports`, not `In-tray`
- Click `Clear` in the search toolbar if any persisted filters are active
- If the UI still looks stale after reset, hard refresh once

## Dataset State

After `make demo-reset`, the demo split contains exactly five uploads:

| Sample ID | Subject | Expected state |
| --- | --- | --- |
| `benign_internal_it_notice_001` | `Planned VPN maintenance window` | already resolved safe |
| `malicious_attachment_zip_001` | `Outstanding invoice 4481` | already resolved malicious |
| `benign_vendor_portal_notice_001` | `Monthly portal notice for April` | open benign control |
| `display_name_bec_replyto_001` | `Need you to handle this wire today` | open spoof / BEC-style case |
| `cred_harvest_shortener_001` | `Urgent: Your Microsoft 365 password expires today` | open obvious phishing case |

## 5-Minute Flow

Use this exact report order:

1. `benign_internal_it_notice_001` - `Planned VPN maintenance window`
2. `malicious_attachment_zip_001` - `Outstanding invoice 4481`
3. `benign_vendor_portal_notice_001` - `Monthly portal notice for April`
4. `display_name_bec_replyto_001` - `Need you to handle this wire today`
5. `cred_harvest_shortener_001` - `Urgent: Your Microsoft 365 password expires today`

### 0:00-0:30 Reset and login

1. Run `make demo-reset`.
2. Open `http://localhost:3000/login`.
3. Sign in with `admin / change-me`.
4. Open `Uploads`.

Talk track:

`This is a deterministic demo environment. I can reset it to the same known dataset before every call.`

### 0:30-1:00 Show the queue

1. Confirm there are five uploads.
2. If the list is not obviously in the sequence above, use the search bar to jump by subject.
3. Explain the order:
   - one resolved safe baseline
   - one resolved malicious baseline
   - one open benign control
   - one open spoof / BEC case
   - one open obvious phishing case
4. Point out that the visible queues are intentionally simple:
   - `Needs investigation`
   - `Likely benign`
   - `Uncertain`
5. Explain that this is an analyst workspace, not a black-box auto-close tool.

Talk track:

`The goal is to cut analyst time by putting the right cases in front of them with evidence already organized.`

### 1:00-1:45 Show an already resolved malicious case

Open `Outstanding invoice 4481`.

Click path:

1. Open the report.
2. Go to `Attachments`.
3. Show the suspicious archive attachment and hash.
4. Open the actions menu `•••`.
5. Click `Download` -> `PDF`.
6. Click `Download` -> `IOC CSV` or `IOC JSON`.

Talk track:

`This is what a closed malicious case looks like. The analyst decision is preserved, the evidence can be exported immediately, and the IOC package is ready for downstream handling.`

### 1:45-2:15 Show an already resolved safe case

Open `Planned VPN maintenance window`.

Click path:

1. Open the report.
2. Go to `Authentication`.
3. Show that SPF, DKIM, and DMARC are clean.
4. Open `•••` -> `Audit log`.

Talk track:

`Not every reported email is phishing. The point is to get to a defensible safe decision quickly and keep the audit trail.`

### 2:15-2:45 Show the open benign control

Open `Monthly portal notice for April`.

Click path:

1. Open the report.
2. Go to `URLs`.
3. Show the stable vendor portal URL.
4. Go to `Authentication`.
5. Show that SPF, DKIM, and DMARC are aligned.
6. Leave the report open.

Talk track:

`This is the control. It looks routine, it stays low-friction to inspect, and the analyst can decide whether to leave it open briefly or resolve it safe later.`

### 2:45-3:45 Resolve the spoof / BEC-style case live

Open `Need you to handle this wire today`.

Click path:

1. Open the report.
2. Go to `Details`.
3. Show `From` and `Reply-To`.
4. Go to `Authentication`.
5. Point out the DMARC issue and why it is suspicious even without a link.
6. Click `Resolve`.
7. Leave `Disposition` as `Malicious`.
8. Set `Classification code` to `SPOOF`.
9. Click `Resolve`.

Talk track:

`This is the more operationally interesting case because it is not just a bad link. The analyst still gets the key evidence quickly and can close the case without bouncing across multiple tools.`

### 3:45-4:45 Resolve one obvious phishing case live

Open `Urgent: Your Microsoft 365 password expires today`.

Click path:

1. Open the report.
2. Go to `URLs`.
3. Show the shortener, redirect chain, and final domain.
4. Go to `Authentication`.
5. Point out auth failures.
6. Optionally go to `Source` and show `Original message` preservation.
7. Click `Resolve`.
8. Leave `Disposition` as `Malicious`.
9. Set `Classification code` to `CRED_HARV`.
10. Keep or review the preselected flagged artifacts.
11. Click `Resolve`.

Talk track:

`This is the happy-path phishing case. You can see the redirect chain, failed auth, preserved original message, and then resolve it in one place.`

### 4:45-5:00 Close on auditability and deployment

Return to `Uploads` or stay on the current report.

Close with:

- `Analyst-in-the-loop resolution`
- `Evidence export and IOC export`
- `Audit log on every resolution`
- `Original uploaded sample preserved`
- `Compose-based local deployment today, on-prem direction by design`

Suggested closing line:

`The product thesis is not full autonomy. It is faster, evidence-backed phishing decisions with a clear audit trail and a deployment model that fits sensitive environments.`

## Backup Order If Time Gets Tight

If you only have 3 minutes:

1. Queue overview in `Uploads`
2. `Urgent: Your Microsoft 365 password expires today`
3. `Outstanding invoice 4481`
4. End on `Audit log` + `PDF` + `IOC CSV`

## Common Failure Recovery

If the dataset is wrong:

```bash
make demo-reset
```

If old queue filters are still applied:

- Click `Clear` in the search toolbar

If you need the broader evaluation set instead of the curated walkthrough:

```bash
make demo-reset SPLIT=gold
```
