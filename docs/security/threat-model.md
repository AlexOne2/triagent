# Threat Model

This document describes the security posture of the current public Triagent demo. It is meant to be concrete about what the repository does today, what it defends against, and what remains out of scope.

## Scope

In scope for this threat model:

- manual `.eml` and `.msg` ingestion through the web UI and API
- parsing and normalization of headers, message bodies, URLs, and attachments
- analyst review in the Next.js frontend
- evidence export and tamper-evident audit logging
- artifact storage in MinIO and metadata storage in PostgreSQL

Out of scope for this threat model:

- malware detonation or full sandbox execution
- enterprise mail gateway enforcement or mailbox remediation
- data loss prevention outside the application boundary
- workstation hardening outside the guidance in the hardening guide

## Security Objectives

The current demo is trying to preserve these properties:

- reported emails and attachments are treated as untrusted input
- analysts can inspect suspicious content without silently losing provenance
- original samples, attachments, and audit history are preserved with traceability
- case actions are attributable to authenticated users or API keys
- audit history is difficult to tamper with without detection

## Primary Assets

- uploaded original email samples (`.eml` / `.msg`)
- extracted attachments and their hashes
- parsed message metadata, headers, and rendered body content
- analyst decisions, flagged artifacts, and case notes
- audit events and audit export manifests
- user sessions, API keys, and role assignments

## Trust Boundaries

### 1. Analyst Browser

The browser displays untrusted message content, authentication details, URLs, raw headers, and attachment metadata.

Important current behavior:

- HTML message rendering is done inside a sandboxed `<iframe>` in the report view
- raw source is available for analyst inspection
- attachments and original samples can be downloaded by authorized users

This boundary is still sensitive because the analyst workstation is where suspicious content is ultimately viewed and downloaded.

### 2. FastAPI Backend

The backend parses uploaded messages, computes hashes and scores, performs optional URL resolution, and exposes report, export, and audit APIs.

It is trusted to:

- validate and normalize uploaded content
- enforce RBAC on report and admin actions
- avoid logging sensitive message bodies into audit metadata
- preserve original-message and attachment provenance

### 3. PostgreSQL

PostgreSQL stores report metadata, analyst decisions, RBAC state, and the audit chain state.

It does not store attachment blobs or original-message blobs directly.

### 4. MinIO Object Storage

MinIO stores attachment blobs and original-message blobs. Object names are normalized and include hash-derived prefixes, but the objects themselves remain untrusted analyst artifacts.

### 5. External Network Services

When enabled, Triagent may contact external systems for enrichment-like behavior:

- DNS lookups used by authentication summary logic
- URL resolution requests used to follow redirects and shorteners

These create egress and privacy considerations. In isolated or highly sensitive environments, these controls should be disabled or proxied.

## Threat Actors

### Malicious External Sender

Capabilities:

- can send malformed or deceptive email content
- can embed phishing links, shorteners, attachments, and spoofing indicators
- can try to trigger risky analyst behavior through downloads or rendered content

### Malicious or Careless Internal User

Capabilities:

- can upload samples that should not have been uploaded
- can misclassify reports
- can attempt to abuse broad administrative permissions

### Compromised Analyst Account or API Key

Capabilities:

- can read case data allowed by the compromised principal
- can resolve, reopen, or export data according to the compromised permissions

### Operator Misconfiguration

Capabilities:

- can expose backend, database, or object storage services to untrusted networks
- can leave demo credentials unchanged
- can enable risky enrichment behavior without egress controls

## Key Threats and Current Controls

## Threat: Malicious HTML or message content in analyst review

Current controls:

- rendered HTML is displayed in a sandboxed iframe
- raw source and plaintext views are available so analysts can inspect without trusting rendered content

Residual risk:

- Triagent is not a remote browser isolation system
- analysts can still click links or download samples if their workstation hygiene is weak

## Threat: Malicious attachment execution after download

Current controls:

- attachments are stored as blobs, not executed by the platform
- filenames are normalized before object storage
- SHA-256 values are calculated and surfaced for analyst review

Residual risk:

- Triagent does not detonate attachments
- downloading an attachment transfers the risk to the analyst environment

## Threat: Loss of original sample provenance

Current controls:

- the original uploaded message is preserved as a first-class stored artifact
- attachments and original messages are hash-addressed and downloadable through authenticated endpoints

Residual risk:

- provenance helps with traceability, but it does not prove an uploaded file was itself benign

## Threat: Audit-log tampering

Current controls:

- audit events are append-only
- each event is hash-chained with the previous event
- audit metadata is sanitized and size-bounded
- audit verification and export workflows are available

Residual risk:

- an attacker with full database control can still destroy availability
- tamper evidence is strongest when exports and backups are also protected

## Threat: Sensitive data leakage through enrichment

Current controls:

- URL resolution is configurable and bounded by timeout and hop limits
- DNS-based authentication helpers are configurable

Residual risk:

- if URL resolution or DNS lookups are enabled, suspicious data may cause outbound network traffic
- the prototype does not yet provide a dedicated egress proxy or privacy-preserving enrichment service

## Threat: Weak authentication or over-broad access

Current controls:

- session-based RBAC is the default auth mode
- lockout and password-policy settings exist
- built-in roles separate analyst, reviewer, read-only, ingestor, and admin behavior

Residual risk:

- the repo still ships with convenience defaults in `infra/.env.example`
- the legacy basic-auth bridge exists and should not remain enabled in hardened deployments

## Known Gaps

These gaps are material and should be treated as part of the current prototype scope:

- no malware sandbox or detonation workflow
- no attachment handoff flow to isolated analysis environments
- no remote browser isolation or content-disarm pipeline
- no formal secret manager integration
- no enterprise SSO or device-trust controls in the prototype
- no explicit outbound proxy model for URL resolution or DNS lookups
- no signed release, SBOM, or rollback automation yet

## Assumptions

This threat model assumes:

- the backend host, Postgres, and MinIO are operated by the same trusted organization
- TLS and network segmentation are added outside the demo defaults
- analysts understand that downloaded samples remain untrusted
- operators rotate all demo credentials before shared use

## References

- [Deployment hardening guide](../operations/hardening.md)
- [Rollback runbook](../operations/runbook-rollback.md)
