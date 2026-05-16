# Security Policy

Triagent handles suspicious email artifacts, headers, URLs, attachments, and analyst decisions. Please treat security reports and sample data with care.

## Supported Scope

This repository is a public prototype of the Triagent codebase. Security reports are welcome for the current `main` branch.

In scope:

- authentication, session, RBAC, or API key bypasses
- unsafe file upload or attachment handling behavior
- path traversal, arbitrary file read/write, or object storage exposure
- sensitive data leakage through logs, exports, audit metadata, or API responses
- SSRF, command execution, SQL injection, XSS, and CSRF issues
- insecure defaults that could affect self-hosted deployments

Out of scope:

- findings that require already-compromised host or database access
- denial-of-service reports without a practical security impact
- vulnerability reports against third-party services not operated by Triagent
- test data that is clearly synthetic and intentionally included in the repository

## Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected vulnerability.

Use GitHub private vulnerability reporting if it is enabled for this repository. If private reporting is not available, contact the repository maintainer directly and avoid including real customer data, live malicious attachments, credentials, or private email contents in the first message.

Helpful report details:

- affected commit or version
- affected component: backend, frontend, Outlook add-in, Docker/infra, parser, export, or auth
- reproduction steps using synthetic data when possible
- observed impact
- recommended fix, if known

## Handling Suspicious Samples

Do not attach live malware, private customer emails, production credentials, or real incident data to public issues or pull requests. Use minimal synthetic samples that reproduce the behavior.

## Disclosure Expectations

Triagent aims to acknowledge credible vulnerability reports promptly and coordinate fixes before public disclosure. Because this is currently a prototype, response timelines may vary, but vulnerability reports will be prioritized over ordinary feature work.
