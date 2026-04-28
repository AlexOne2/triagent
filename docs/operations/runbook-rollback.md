# Rollback Runbook

This runbook is for the current Compose-based prototype. It assumes the backend, PostgreSQL, and MinIO are operated together and that upgrades may include both code and Alembic migrations.

The safest rollback path is restore-and-redeploy, not an ad hoc schema downgrade.

## When to Use This Runbook

Use this runbook if any of the following occurs after a change:

- backend fails to start after a migration or image update
- login works but report detail pages or exports fail
- report artifacts or original-message downloads break
- audit verification fails after the change
- analysts report clear regressions in ingest, resolution, or export behavior

## Preconditions

Before relying on rollback, you should already have:

- a known-good git commit or image tag
- a PostgreSQL backup taken before the change
- a MinIO backup or snapshot taken before the change
- a copy of `infra/.env`

If you do not have both database and object-storage backups, rollback may restore the UI while leaving report artifacts inconsistent.

## Pre-Change Checklist

Before applying a migration or changing deployed code:

1. Record the currently deployed commit or image tag.
2. Record the current `infra/.env`.
3. Run `make audit-verify`.
4. Take a PostgreSQL backup.
5. Take a MinIO backup or snapshot.

Recommended validation before change:

```bash
make audit-verify
curl http://localhost:${BACKEND_PORT:-8000}/health
```

## Triage the Failure

Check which class of failure you have:

### A. Backend startup or migration failure

Symptoms:

- backend container exits immediately
- Alembic upgrade fails
- `/health` is unavailable

Actions:

- inspect backend logs
- stop further writes to the system
- prepare to restore the pre-change database and artifacts

### B. Application regression after successful startup

Symptoms:

- `/health` passes, but ingest or report pages fail
- exports fail
- original-message or attachment downloads fail

Actions:

- identify whether the regression is code-only or schema/data related
- if any migration or artifact-storage mutation happened, treat rollback as restore-and-redeploy

## Rollback Procedure

## 1. Stop the Updated Application

Stop the current deployment before attempting restore:

```bash
make down
```

Or use your equivalent Compose invocation if you are not using the Makefile wrapper.

## 2. Restore the Known-Good Code Version

Return the repo or deployment manifests to the last known-good version.

For a git-based local deployment, that usually means checking out the previously validated commit in a separate maintenance step before restarting services.

Do not assume a forward migration can be safely reversed by running `alembic downgrade` unless that exact downgrade path has been tested.

## 3. Restore PostgreSQL From the Pre-Change Backup

Restore the database snapshot taken immediately before the failed deployment.

Rationale:

- the current prototype includes schema migrations
- a code rollback without a schema rollback can leave the app in an undefined state

## 4. Restore MinIO Artifacts From the Matching Backup

Restore the corresponding MinIO snapshot or backup so these remain consistent with the database:

- original-message blobs
- attachment blobs
- audit exports if you store them there

## 5. Start the Known-Good Stack

Bring the previous version back up:

```bash
make dev
```

If you need migrations for the known-good version, run only the migration state that belongs to that version. Do not automatically run `make migrate` against a restored database unless you are certain it is required.

## Post-Rollback Verification

Run this verification checklist before returning the system to analysts:

1. `curl http://localhost:${BACKEND_PORT:-8000}/health`
2. Log in through the frontend.
3. Open a recent report.
4. Verify the report detail view loads:
   - Details
   - Authentication
   - URLs
   - Attachments
   - Source
5. Download an attachment and an original message from a known test report.
6. Export evidence JSON, Markdown, or PDF for a known test report.
7. Run:

```bash
make audit-verify
```

8. Review backend logs for startup, storage, and database errors.

## If Rollback Is Not Immediately Possible

If you cannot restore immediately:

- disable analyst access or communicate a read-only outage window
- stop ingest to avoid creating post-failure data you cannot safely reconcile
- preserve all logs from the failed deployment
- do not continue retrying migrations on the same damaged state without a recovery plan

## Lessons-Learned Checklist

After recovery, record:

- what change triggered the rollback
- whether the failure was code, config, schema, or storage related
- whether backups were complete and recent enough
- whether any runbook step was missing or ambiguous

Update this runbook when the deployment model changes.

## Related Docs

- [Threat model](../security/threat-model.md)
- [Deployment hardening guide](./hardening.md)
