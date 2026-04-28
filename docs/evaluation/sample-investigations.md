# Sample Investigation Scenarios

This document defines the first investigation scenarios the prototype should be able to demonstrate clearly. It is written as evaluation guidance for synthetic or redacted samples rather than as a collection of real customer mail.

Use these scenarios as:

- analyst walkthrough examples
- acceptance criteria for report workflow changes
- regression checks for exports, ATT&CK mapping, IOC generation, and original-message preservation

## Scenario 1: Credential Harvest Through a Shortener

Suggested fixture name:

- `cred-harvest-shortener.eml`

Sample characteristics:

- external sender with a branded display name
- one visible shortened URL such as `bit.ly/...`
- redirect chain ends on a credential collection page
- urgency language in subject or body

Analyst review path:

- Details: confirm sender, display name, and mailbox context
- Authentication: check SPF/DKIM/DMARC outcomes
- URLs: inspect original URL, final URL, final domain, and redirect chain
- Source: verify the original message and raw source were preserved

Expected report behavior:

- elevated risk score
- URL resolution shows the final destination
- resolved URL or final domain can be flagged as malicious
- JSON bundle contains original and resolved URL artifacts
- IOC export includes both the visible URL and the final domain

Expected analyst conclusion:

- resolve as `MALICIOUS`
- classify as `CRED_HARV` if the evidence supports credential collection, otherwise `MAL_URL`

Expected ATT&CK outcome:

- `CRED_HARV` should map to `T1598.003`
- `MAL_URL` should map to `T1566.002`

## Scenario 2: Sender Spoof With Payment-Fraud Pretext

Suggested fixture name:

- `spoofed-payment-request.eml`

Sample characteristics:

- display name appears to be an executive or finance contact
- visible `From` domain differs from `Return-Path` or `Reply-To`
- SPF / DKIM / DMARC fail or misalign
- no attachment required; a reply or payment request is enough

Analyst review path:

- Details: compare `From`, `Reply-To`, and `Return-Path`
- Authentication: verify DMARC and SPF outcomes
- Source: inspect headers for additional spoofing clues

Expected report behavior:

- visible routing-domain mismatch
- auth section surfaces failed or suspicious outcomes
- attacker-controlled reply domain can be flagged as malicious

Expected analyst conclusion:

- resolve as `MALICIOUS`
- classify as `SPOOF` or `FIN_FRAUD` depending on the sample emphasis

Expected ATT&CK outcome:

- `SPOOF` should map to `T1672`
- if a malicious link is also present, expect `T1566.002` in addition to `T1672`

## Scenario 3: Malicious Attachment Delivery

Suggested fixture name:

- `invoice-zip-dropper.msg`

Sample characteristics:

- invoice or shipping pretext
- one suspicious attachment such as `.zip`, `.docm`, or similar
- few or no URLs required

Analyst review path:

- Attachments: review filename, type, size, and SHA-256
- Source: verify the original `.msg` sample is preserved
- Authentication: check whether the sender is external or poorly aligned

Expected report behavior:

- attachment metadata and hash are captured
- attachment can be downloaded for isolated analysis
- flagged artifacts can include attachment name and SHA-256
- IOC export contains file name and file hash

Expected analyst conclusion:

- resolve as `MALICIOUS`
- classify as `MAL_ATTACH`

Expected ATT&CK outcome:

- `T1566.001`

## Scenario 4: Thread Hijack With Malicious Follow-Up

Suggested fixture name:

- `thread-hijack-followup.eml`

Sample characteristics:

- subject begins with an existing conversation pattern such as `Re:`
- `In-Reply-To` or related headers suggest a thread context
- body contains a new malicious link or attachment
- the content attempts to look routine rather than urgent

Analyst review path:

- Details: inspect `In-Reply-To`, sender, and timestamps
- URLs or Attachments: review the payload actually introduced into the thread
- Source: confirm the thread markers in raw headers

Expected report behavior:

- the thread indicators are visible in report details
- malicious payload artifacts can still be flagged independently

Expected analyst conclusion:

- resolve as `MALICIOUS`
- classify as `THREAD_HIJACK`

Expected ATT&CK outcome:

- if link or attachment evidence is preserved, expect the corresponding `T1566.*` delivery mapping
- if only the thread-hijack pattern is preserved, expect the base phishing technique entry

## Scenario 5: Benign External Newsletter or Vendor Message

Suggested fixture name:

- `benign-newsletter.eml`

Sample characteristics:

- legitimate bulk sender or vendor notification
- aligned sender and routing domains
- expected URLs with no suspicious redirect behavior
- no malicious attachment indicators

Analyst review path:

- Details: verify sender identity
- Authentication: check that SPF / DKIM / DMARC pass or align
- URLs: verify links remain on expected domains

Expected report behavior:

- lower risk score than phishing scenarios
- no obviously malicious artifact flags required
- evidence export still captures the investigation record cleanly

Expected analyst conclusion:

- resolve as `SAFE`

Expected ATT&CK outcome:

- none, or a deliberately empty ATT&CK technique section

## Minimum Regression Checklist

When using these scenarios as a smoke test, verify:

1. original message metadata is present
2. attachments are listed when applicable
3. URL resolution behaves as expected for link-based cases
4. evidence export succeeds for JSON and Markdown or PDF
5. IOC export includes the expected sender, domain, URL, and attachment indicators
6. ATT&CK mappings are present only when the evidence supports them
7. analyst resolution and flagged-artifact state survive a refresh

## Future Fixture Layout

The repository now includes a scaffolded corpus in `test_data/synthetic-corpus/`.
Use it as the home for checked-in synthetic samples and expected outputs:

- `test_data/synthetic-corpus/specs/canonical-scenarios.json`
- `test_data/synthetic-corpus/samples/cred_harvest_shortener_001.eml`
- `test_data/synthetic-corpus/expected/cred_harvest_shortener_001.json`
- `test_data/synthetic-corpus/manifest.json`
- `test_data/synthetic-corpus/splits/gold.json`

The canonical maintenance flow is:

1. Update `specs/canonical-scenarios.json`
2. Regenerate the corpus with `python3 backend/scripts/generate_synthetic_corpus.py`
3. Validate it with `python3 backend/scripts/validate_synthetic_corpus.py`
