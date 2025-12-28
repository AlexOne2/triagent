# MailTriage MVP

On-prem phishing triage MVP with an Outlook add-in, FastAPI backend, and Next.js SOC dashboard.

## Repo Structure

- `backend/`: FastAPI API + SQLAlchemy + Alembic
- `frontend/`: Next.js dashboard
- `outlook-addin/`: Office.js taskpane add-in
- `infra/`: Docker Compose + env templates

## Quickstart (Local)

1) Copy env template:

```
cp infra/.env.example infra/.env
```

2) Run migrations:

```
make migrate
```

3) Start services:

```
make dev
```

4) (Optional) Seed demo data:

```
make seed
```

Dashboard: http://localhost:3000
Backend health: http://localhost:8000/health

## Outlook Add-in (Sideload)

1) Update backend URL + salt:

- Edit `outlook-addin/config.json`
  - If basic auth is enabled, set `apiUsername` / `apiPassword` to match backend.

2) Install add-in deps and start dev server:

```
cd outlook-addin
npm install
npm run dev
```

3) Trust dev certificate (first time):

```
npx office-addin-dev-certs install
```

4) Sideload `outlook-addin/manifest.xml`:

- **Windows (Outlook Desktop)**: File -> Manage Add-ins -> \"Upload My Add-in\" -> select the manifest.
- **macOS (Outlook Desktop)**: Tools -> Accounts -> Advanced -> Custom Add-ins -> \"+\" -> add manifest.
- **Outlook on the web**: Settings -> Manage add-ins -> Upload custom add-in.

## Demo Flow

1) Open the Outlook add-in and click **Report suspicious email**.
2) The backend clusters the report and extracts URLs.
3) Open the dashboard to review clusters and update status.

## API (Backend)

- `POST /api/report`
- `GET /api/clusters`
- `GET /api/clusters/{cluster_id}`
- `PATCH /api/clusters/{cluster_id}`
- `GET /health`

## Notes

- Admin basic auth uses `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars; set `NEXT_PUBLIC_API_USERNAME` / `NEXT_PUBLIC_API_PASSWORD` to match for the dashboard.
- Reporter identity is hashed with `REPORTER_HASH_SALT`.
- MinIO is scaffolded; attachments are not wired in v0.
