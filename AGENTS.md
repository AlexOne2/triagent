# AGENTS.md

This file is the working context for coding agents operating on Triagent. Keep it current when major product direction, repo structure, or implementation priorities change.

## Product Context

Triagent is a local-first, on-prem phishing investigation workspace for SOC analysts and security teams. It turns reported emails into structured cases with parsed headers, authentication results, URLs, attachments, transmission hops, analyst decisions, and exportable evidence.

The product stance is:

- analyst-centered, not blind automation
- local-first and on-prem friendly
- useful for regulated environments where email artifacts should not automatically leave the organization
- a personal public demo / portfolio asset, not a broad community OSS project
- non-commercial use allowed under the PolyForm Noncommercial License 1.0.0
- external code contributions are not currently accepted

The main product goal is to help an analyst move from suspicious email to defensible verdict faster, with cleaner evidence and less repetitive parsing work.

## GTM And Positioning Context

Triagent should not chase broad GitHub traffic first. The better goal is credible security-operator attention: SOC analysts, IR consultants, MSSP operators, Microsoft/M365 security consultants, and security leaders who recognize the workflow pain.

Do not describe Triagent as "open source" while it uses the PolyForm Noncommercial license. Use "source-available", "public demo", or "free for non-commercial evaluation" instead.

Preferred positioning:

> Triagent is a local-first phishing investigation workspace for regulated SOCs that turns messy reported emails into structured, exportable evidence.

Launch/category framing:

> SOC teams do not just need better phishing detection. They need faster, auditable investigation workflows for messy reported emails.

Avoid leading with "AI phishing detection". That phrasing is crowded and makes the product sound like vapor. Lead with evidence workflow, analyst workload, auditability, local-first/on-prem posture, and messy `.eml` / `.msg` reality.

Good launch title shape:

- "Phishing triage is not a detection problem. It is an evidence workflow problem."
- "Every reported phishing email becomes analyst paperwork. I built Triagent to reduce that."
- "Show HN: I built a local-first PhishTool-style workspace for phishing triage in regulated SOCs."

Launch-readiness items before serious promotion:

- Add a 60-second demo GIF or video near the top of the README.
- Add a "Try the demo in 5 minutes" path.
- Publish a `v0.1` GitHub release.
- Add GitHub topics: `phishing`, `soc`, `incident-response`, `security-tools`, `email-security`, `dfir`, `threat-intelligence`, `on-prem`, `fastapi`, `nextjs`.
- Rename any "personal portfolio asset" wording if it makes operator-facing pages feel unserious; "validation prototype" is usually better for public-facing copy.
- Keep the license story honest: source-available / non-commercial unless the license changes.

Preferred first distribution loop:

1. Private operator seeding with 20-30 relevant people.
2. LinkedIn launch essay aimed at security operators.
3. Show HN only after repo/demo quality is high.
4. Reddit only through pain/research-oriented discussions, not drive-by repo promotion.

Target first-30-day metrics:

- 30 stars from relevant security people, not random velocity.
- 10 calls or substantial feedback threads with SOC / IR / MSSP people.
- 5 concrete feedback notes from real operators.
- 3 people asking to test against their workflow.
- 1 design partner or serious evaluator.
- 1 public technical post with useful security-practitioner comments.

Useful content assets:

- "Open Phishing Triage Workflow Checklist"
- "What I learned from 20 SOC people reviewing Triagent"
- "Building tamper-evident audit logs for phishing investigations"
- "Why AI phishing tools fail without evidence workflow"
- fair comparison docs such as Triagent vs PhishTool, M365 submission portal, TheHive, or SOAR playbooks

## Current Repo Shape

```text
backend/        FastAPI API, SQLAlchemy models, Alembic migrations, parser services
frontend/       Next.js analyst workspace
outlook-addin/  Office.js Outlook taskpane add-in
infra/          Docker Compose stack and environment templates
docs/           roadmap, threat model, hardening, rollback, demo, evaluation docs
test_data/      synthetic phishing corpus and expected outputs
assets/         public screenshots only
```

## Tech Stack

- Backend: FastAPI, SQLAlchemy, Alembic, Pydantic
- Frontend: Next.js 14, React 18, TypeScript, Recharts
- Database: PostgreSQL
- Object storage: MinIO
- Deployment: Docker Compose
- Outlook add-in: Office.js, Webpack, TypeScript
- Email parsing: Python email tooling plus MSG parser service

## Important Commands

Create local env:

```bash
cp infra/.env.example infra/.env
```

Run migrations:

```bash
make migrate
```

Start local stack:

```bash
make dev
```

Import synthetic corpus:

```bash
make import-synthetic SPLIT=gold
```

Reset demo walkthrough:

```bash
make walkthrough-reset
```

Frontend build:

```bash
cd frontend
npm run build
```

Outlook add-in build:

```bash
cd outlook-addin
npm run build
```

## Current Capabilities

- `.eml` and `.msg` ingestion
- Outlook add-in submission flow
- report queue and in-tray
- report detail tabs for details, authentication, URLs, attachments, transmission, and headers
- structured SPF/DKIM/DMARC/ARC display
- URL and domain extraction
- attachment metadata, hashes, download, and flagging
- analyst resolution workflow with classification codes, notes, flagged artifacts, reopen flow, and audit history
- evidence exports in Markdown, PDF, JSON, and IOC formats
- session auth, RBAC, API keys, and first-pass LDAP integration
- hash-chained audit log
- Docker Compose local deployment

## Product Principles

- Prefer clarity over cleverness.
- Preserve analyst control. AI should draft, explain, and suggest, not silently decide.
- Keep suspicious artifacts local by default.
- Make evidence export boringly reliable.
- Avoid broad platform sprawl; strengthen the investigation core first.
- Demo quality matters. A public repo should make the product feel credible in the first 60 seconds.
- Do not add real customer emails, live malware, credentials, private interview notes, pitch decks, or sensitive PDFs to the public repo.

## Prioritized Roadmap

### 1. Replace AI Draft Slop With Analyst Verdict Draft

Current issue: the existing analyst verdict draft can feel like generic generated output. It should become a disciplined analyst verdict draft.

Target behavior:

- Rename/position it as "Analyst Verdict Draft" or "Proposed Analyst Draft", not an AI verdict.
- Produce a concise proposed disposition: malicious, suspicious, or safe.
- Include confidence and uncertainty.
- Explain the evidence that supports the draft.
- List missing evidence and what would change the conclusion.
- Suggest classification code.
- Suggest flagged artifacts.
- Never auto-resolve a case.
- Require human review before resolution.

Implementation direction:

- Improve prompt/context construction around actual parsed artifacts.
- Make output schema strict and compact.
- Add tests with known synthetic/human-crafted cases.
- Render the draft in the resolution drawer as editable analyst assistance.

Success criterion:

- The draft reads like a careful junior analyst prepared it, not like a generic chatbot summary.

### 2. Replace AI-Generated Datasets With Human-Crafted Mail Samples

Current issue: generated datasets are useful for coverage but can feel synthetic and reduce credibility.

Target behavior:

- Build a smaller but excellent public corpus of human-crafted, safe phishing-like emails.
- Cover realistic cases:
  - credential harvest with direct link
  - credential harvest with shortener/redirect
  - benign internal notification
  - BEC/display-name spoof
  - malicious attachment lure using harmless dummy attachment
  - calendar invite / `.ics` attachment
  - thread-hijack style follow-up
  - suspicious but ultimately safe false positive
- Include expected outputs and analyst notes.
- Keep all samples synthetic, safe, and clearly documented.

Implementation direction:

- Treat sample quality as a product feature.
- Keep expected JSON fixtures for parser regression tests.
- Add a sample gallery in docs with screenshots and expected verdicts.

Success criterion:

- A visitor can inspect the sample cases and feel that Triagent understands real phishing workflows.

### 3. Make The Demo Awesome

Current issue: the project has demo commands, but the demo should feel curated and intentional.

Target behavior:

- One command creates a polished demo environment.
- Demo data is deterministic.
- The default queue shows a small set of compelling cases.
- Each case demonstrates a specific capability.
- README points users to a guided 5-minute walkthrough.

Implementation direction:

- Strengthen `make walkthrough-reset`.
- Add or improve `docs/demo-script.md`.
- Add screenshots for the best flows.
- Consider a `make demo` alias if it improves discoverability.

Success criterion:

- Someone can run the demo and understand the product without a live explanation.

### 4. Improve URL Analysis

Target behavior:

- Normalize URLs consistently.
- Extract original URL, display text when available, normalized URL, domain, and final landing domain.
- Expand shortened URLs safely.
- Preserve redirect chain.
- Flag suspicious cases where the first hop looks benign but the final destination does not.
- Detect suspicious URL traits:
  - punycode or lookalike domains
  - raw IP hosts
  - userinfo abuse
  - excessive redirects
  - mismatched displayed URL vs actual URL
  - unusual ports

Implementation direction:

- Keep network behavior explicitly configurable.
- Avoid mandatory cloud enrichment.
- Store redirect analysis separately from raw extracted URLs.
- Render URL chains compactly in the URL tab.

Success criterion:

- The URL tab becomes one of the strongest parts of the product.

### 5. Add Investigation Bundle Export

Target behavior:

- Every report can export a complete investigation bundle:
  - `evidence.json`
  - `report.md`
  - `iocs.csv`
  - original `.eml` or `.msg`
  - attachment metadata and optionally attachment files
  - redirect-chain data
  - resolution history
  - case-scoped audit trail
- Bundle should be deterministic and easy to hand to another analyst or attach to an incident record.

Implementation direction:

- Start with a `.zip` endpoint.
- Reuse existing evidence export logic rather than duplicating formatting code.
- Add tests for bundle contents and filenames.

Success criterion:

- The bundle becomes the artifact people remember: Triagent converts a messy email into a clean investigation package.

### 6. Build A Local CLI

Target behavior:

```bash
triagent analyze suspicious.eml --out case_bundle/
```

The CLI should work without the full web stack for local analysis.

Implementation direction:

- Extract parser and export logic into reusable backend services first.
- Start with `.eml` support.
- Output normalized JSON and Markdown.
- Add `.msg`, attachments, IOC export, and redirect handling later.

Success criterion:

- A technical evaluator can get value in under 10 minutes without Docker Compose.

### 7. Add Sandbox Integration Without Building A Sandbox

Target behavior:

- Triagent should broker attachment analysis, not detonate files itself.
- Support an on-prem / air-gapped sandbox workflow.
- Keep Joe Sandbox or similar tools as integrations, not core dependencies.

Implementation direction:

- Add a sandbox provider interface.
- Start with manual workflow states:
  - not submitted
  - submitted externally
  - result attached
  - failed / unavailable
- Store sandbox report metadata and analyst notes.
- Later add provider-specific connectors.

Success criterion:

- Analysts can track attachment handoff and sandbox results without Triagent sending files to a cloud service by default.

### 8. Improve Evidence Quality And Case Completeness

Target behavior:

- Add an evidence completeness indicator, not a phishing verdict score.
- Show whether a case has:
  - original message
  - complete headers
  - authentication summary
  - URLs extracted
  - redirect chain resolved
  - attachments hashed
  - analyst notes
  - flagged artifacts
  - evidence export generated

Success criterion:

- Analysts can tell whether a case is ready to resolve or still missing investigation work.

## Design Notes

- Current UI uses a slate + teal system.
- Teal is the brand/action color.
- Green is reserved for safe/resolved/pass states.
- Red is reserved for malicious/destructive/fail states.
- Amber is reserved for suspicious/open/needs-review states.
- Keep the UI compact. The user prefers a slightly dense analyst workstation feel.
- Avoid broad redesigns unless requested; improve one workflow at a time.

## Repo Hygiene Rules

- Keep `assets/` limited to public screenshots and safe visual assets.
- Do not commit `.env`, logs, local caches, `.DS_Store`, private PDFs, interview notes, pitch decks, or generated build artifacts.
- Use synthetic data for examples and tests.
- If private data was ever committed, consider history cleanup with `git filter-repo` or BFG before treating the repo as public.

## Licensing And Public Posture

- License: PolyForm Noncommercial License 1.0.0.
- Non-commercial use is allowed.
- Commercial use requires separate permission.
- External code contributions are not accepted at this stage.
- Security issues should be reported privately according to `SECURITY.md`.

## When Picking Work

Default priority:

1. analyst verdict draft quality
2. human-crafted sample cases and demo quality
3. URL analysis
4. investigation bundle export
5. local CLI
6. sandbox integration
7. evidence quality/completeness indicators

Choose small, shippable increments. Prefer improvements that make the public demo more credible and the analyst workflow more obviously useful.

## GTM Work Priority

When working on public-demo and GTM credibility, prioritize:

1. make the demo excellent and quick to run
2. add 60-second GIF/video and better top-of-README demo path
3. create human-crafted sample cases and a sample case gallery
4. publish `v0.1` release once the demo path is stable
5. write the phishing-triage evidence workflow essay
6. create the phishing triage workflow checklist
7. seed privately with real security operators before broad public launch
