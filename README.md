# MailTriage MVP

On-prem phishing triage MVP with an Outlook add-in, FastAPI backend, and Next.js SOC dashboard.

## Repo Structure

- `backend/`: FastAPI API + SQLAlchemy + Alembic
- `frontend/`: Next.js dashboard (uploads, in-tray, report detail, dashboard, admin)
- `outlook-addin/`: Office.js taskpane add-in
- `infra/`: Docker Compose + env templates

## Quickstart (Local)

1) Copy env template:

```bash
cp infra/.env.example infra/.env
```

2) Run migrations:

```bash
make migrate
```

3) Start services:

```bash
make dev
```

4) (Optional) Seed demo data:

```bash
make seed
```

Dashboard: http://localhost:3000
Backend health: http://localhost:8000/health

## Authentication and RBAC

- Auth mode defaults to `session_rbac`.
- On backend startup, if no users exist and `ADMIN_USERNAME` / `ADMIN_PASSWORD` are set, an initial admin user is bootstrapped.
- Login at `http://localhost:3000/login` using that admin user.
- Legacy basic-auth bridge can be enabled/disabled with `AUTH_LEGACY_BASIC_ENABLED`.

### Core permissions

- `reports.read`, `reports.ingest`, `reports.resolve`, `reports.reopen`, `reports.admin_override`
- `resolutions.read`, `dashboard.read`
- `admin.users.read`, `admin.users.write`, `admin.roles.read`, `admin.api_keys.manage`
- `audit.read`, `audit.export`, `audit.verify`, `audit.archive.manage`

### Built-in roles

- `ADMIN`, `ANALYST`, `REVIEWER`, `READ_ONLY`, `INGESTOR`

## Outlook Add-in (Sideload)

1) Update backend URL and API key:

- Edit `outlook-addin/config.json`
  - `backendUrl`
  - `apiKey` (create one from Admin -> API Keys, role `INGESTOR`)

2) Install add-in deps and start dev server:

```bash
cd outlook-addin
npm install
npm run dev
```

3) Trust dev certificate (first time):

```bash
npx office-addin-dev-certs install
```

4) Sideload `outlook-addin/manifest.xml`:

- **Windows (Outlook Desktop)**: File -> Manage Add-ins -> Upload My Add-in -> select the manifest.
- **macOS (Outlook Desktop)**: Tools -> Accounts -> Advanced -> Custom Add-ins -> "+" -> add manifest.
- **Outlook on the web**: Settings -> Manage add-ins -> Upload custom add-in.

## Demo Flow

1) Login in the UI.
2) Upload a `.eml` from Uploads, or use add-in ingestion.
3) Open report detail and resolve/reopen via Resolve drawer.
4) Review history and dashboard aggregations.
5) Manage users/roles and API keys from Admin pages.

## API (Backend)

### Auth

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Admin

- `GET /api/admin/roles`
- `GET /api/admin/permissions`
- `GET /api/admin/users`
- `POST /api/admin/users`
- `PATCH /api/admin/users/{user_id}`
- `PUT /api/admin/users/{user_id}/roles`
- `POST /api/admin/api-keys`
- `GET /api/admin/api-keys`
- `POST /api/admin/api-keys/{id}/revoke`
- `GET /api/admin/audit/events`
- `GET /api/admin/audit/events/{event_id}`
- `GET /api/admin/audit/verify`
- `GET /api/admin/audit/export.ndjson`
- `GET /api/admin/audit/exports`

### Reports and dashboard

- `POST /api/report`
- `POST /api/report-eml` (multipart `.eml` upload)
- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `PATCH /api/reports/{report_id}` (admin override)
- `POST /api/reports/{report_id}/resolve`
- `POST /api/reports/{report_id}/reopen`
- `GET /api/reports/{report_id}/resolutions`
- `GET /api/dashboard/overview?start=<ISO>&end=<ISO>&tz=<IANA>`
- `GET /api/reports/stats`
- `GET /health`

## Notes

- Reporter identity is hashed with `REPORTER_HASH_SALT`.
- MinIO is scaffolded; attachments are not wired in v0.
- Audit events are append-only and hash-chained (`prev_hash`, `event_hash`) for tamper evidence.
- Audit metadata is redacted and size-bounded (`AUDIT_MAX_METADATA_BYTES`) to avoid logging secrets.

## Audit Operations

- Verify chain integrity:

```bash
make audit-verify
```

- Export a window to NDJSON and persist export manifest:

```bash
make audit-export START=2026-02-01T00:00:00Z END=2026-02-20T23:59:59Z
```

- Prune old exported rows beyond retention policy:

```bash
make audit-prune
```

- Relevant env vars:
  - `AUDIT_RETENTION_DAYS`
  - `AUDIT_EXPORT_ENABLED`
  - `AUDIT_EXPORT_STORAGE` (`filesystem` or `minio`)
  - `AUDIT_EXPORT_BUCKET`, `AUDIT_EXPORT_PATH`
  - `AUDIT_MAX_METADATA_BYTES`
