# Deployment Hardening Guide

This guide is for running the current public Triagent demo in a safer shared environment than the default local Compose setup. It is not a production certification checklist, but it should materially reduce avoidable risk.

## 1. Change All Demo Defaults

Do not deploy with the defaults from `infra/.env.example`.

At minimum, change:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `REPORTER_HASH_SALT`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`
- `MINIO_ACCESS_KEY`
- `MINIO_SECRET_KEY`
- `POSTGRES_PASSWORD`

Rationale:

- the repository intentionally ships with convenience values such as `change-me` and `minioadmin`
- reusing those values defeats every higher-level control in the stack

## 2. Disable the Legacy Basic-Auth Bridge

Set:

```env
AUTH_LEGACY_BASIC_ENABLED=false
```

Rationale:

- the public demo still supports a temporary legacy bridge for convenience
- hardened deployments should use the main session-RBAC path, or a reviewed LDAP-backed configuration if needed

## 3. Restrict CORS and External Reachability

Set `CORS_ORIGINS` to the exact analyst UI origin, for example:

```env
CORS_ORIGINS=https://triagent.example.internal
```

Do not leave wildcard-equivalent behavior in place via reverse-proxy rewrites or overly broad origin lists.

Also:

- expose only the frontend and the backend entrypoint that must be reachable
- do not expose PostgreSQL directly to analyst networks
- do not expose MinIO directly to untrusted networks unless you have a deliberate access model

## 4. Put the App Behind TLS

Terminate TLS at a reverse proxy or ingress in front of the frontend and backend.

Recommended baseline:

- HTTPS for the analyst UI
- HTTPS for API traffic
- internal-only connectivity for Postgres and MinIO

The public demo does not configure TLS for you.

## 5. Use Role Separation Deliberately

Do not give every user `ADMIN`.

Use the built-in roles intentionally:

- `INGESTOR` for add-ins or service accounts that only submit mail
- `READ_ONLY` for stakeholders who need visibility but not case mutation
- `ANALYST` / `REVIEWER` for investigation users
- `ADMIN` only for trusted operators

Review API keys regularly and revoke stale keys.

## 6. Treat URL Resolution and DNS Lookups as Egress

Triagent can perform outbound work when these features are enabled:

- authentication DNS lookups via `AUTH_DNS_ENABLED`
- redirect resolution via `URL_RESOLUTION_ENABLED`

If your environment is sensitive or isolated, disable them:

```env
AUTH_DNS_ENABLED=false
URL_RESOLUTION_ENABLED=false
```

If you keep them enabled:

- prefer controlled egress through a proxy or filtered outbound path
- keep `URL_RESOLUTION_VERIFY_TLS=true`
- keep timeout and hop limits low

These URL-resolution settings are supported by backend configuration even if they are not pre-populated in `infra/.env.example`.

## 7. Protect Postgres and MinIO as Internal Dependencies

The application depends on:

- PostgreSQL for metadata, RBAC, and the audit chain
- MinIO for original-message and attachment blobs

Recommended posture:

- keep them on private network segments
- require strong credentials
- back them up together
- monitor storage growth and failed access attempts

If you move MinIO behind HTTPS, update `MINIO_ENDPOINT` accordingly.

## 8. Protect Audit Integrity Operationally

Triagent provides tamper-evident audit chaining, but operators still need to preserve that data.

Recommended practices:

- run `make audit-verify` before and after significant maintenance
- export audit data on a retention cadence
- keep audit exports separate from the live database
- monitor `AUDIT_RETENTION_DAYS`, `AUDIT_EXPORT_ENABLED`, `AUDIT_EXPORT_STORAGE`, and `AUDIT_EXPORT_PATH`

Hash chaining is strongest when paired with independent backups and retained exports.

## 9. Handle Suspicious Samples Safely

The platform stores and surfaces suspicious content, but it does not neutralize it.

Analyst safety recommendations:

- download original messages and attachments only onto approved investigation systems
- do not open suspicious samples on a general-purpose workstation
- use separate tooling for detonation, macro analysis, or active content execution

Current reality:

- HTML rendering is sandboxed in the UI
- attachments are not executed by the platform
- downloaded artifacts are still untrusted

## 10. Back Up Before Changes

Before upgrades or schema changes, back up:

- PostgreSQL
- MinIO objects for report artifacts and original messages

If you can only restore one but not the other, you may lose report-to-artifact consistency.

## 11. Validate the Deployment After Hardening

Use this quick post-change check:

1. Confirm `/health` returns success.
2. Log in through the intended frontend origin.
3. Open a report and verify details, authentication, URLs, and source tabs load.
4. Download an original sample or attachment using an authorized account.
5. Export evidence and IOCs.
6. Run `make audit-verify`.

## Recommended Baseline `.env` Overrides

Example starting point for a shared internal deployment:

```env
ADMIN_PASSWORD=<strong-random-value>
REPORTER_HASH_SALT=<strong-random-value>
POSTGRES_PASSWORD=<strong-random-value>
MINIO_ROOT_USER=<non-default-user>
MINIO_ROOT_PASSWORD=<strong-random-value>
MINIO_ACCESS_KEY=<strong-random-value>
MINIO_SECRET_KEY=<strong-random-value>
CORS_ORIGINS=https://triagent.example.internal
AUTH_LEGACY_BASIC_ENABLED=false
URL_RESOLUTION_VERIFY_TLS=true
```

Add:

- `AUTH_DNS_ENABLED=false` if outbound DNS lookups are not acceptable
- `URL_RESOLUTION_ENABLED=false` if suspicious URL egress is not acceptable

## Related Docs

- [Threat model](../security/threat-model.md)
- [Rollback runbook](./runbook-rollback.md)
