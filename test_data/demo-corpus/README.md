# Modern Demo Corpus

This corpus is the polished public-demo dataset for Triagent. It is separate
from the broader synthetic regression corpus so demos can stay focused,
credible, and easy to reset.

The messages are human-crafted synthetic `.eml` samples. They are inspired by
real phishing workflows, but they do not contain real brands, live malicious
URLs, or active payloads.

## What It Covers

- Credential-harvest redirects
- Benign-looking first hops with suspicious final domains
- Vendor invoice attachment handling
- Compromised-vendor style links with valid authentication
- Executive payment fraud with reply-to mismatch
- QR/login lures with inert image attachments
- Benign vendor and internal IT controls

## Commands

Refresh the generated `.eml` files, expectations, splits, and manifest:

```bash
make generate-demo-corpus
```

Import the curated demo split into a running local stack:

```bash
make import-demo-corpus
```

Reset the local app into a demo-ready state with a mix of open and resolved
cases:

```bash
make demo-reset
```

Validate the generated corpus:

```bash
make validate-demo-corpus
```

## Safety Rules

- Use reserved `.example` domains only.
- Use documentation IP ranges only.
- Keep all attachments inert.
- Keep redirect chains deterministic through `redirect-fixtures.json`.
- Do not copy public phishing samples into this folder.
