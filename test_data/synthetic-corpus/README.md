# Synthetic Corpus Scaffold

This directory contains the first synthetic-corpus scaffold for Triagent.

The corpus is designed to exercise Triagent's actual analysis surface, not
just "phishing vs ham" text classification. Each sample is intended to be a
valid email artifact that can drive some combination of:

- `.eml` parsing
- MIME and attachment extraction
- SPF / DKIM / DMARC parsing from headers
- URL extraction and deterministic redirect resolution
- original-message preservation
- IOC export
- ATT&CK mapping
- analyst classification and campaign grouping

## Layout

- `specs/canonical-scenarios.json`: source-of-truth sample catalog
- `samples/`: generated `.eml` artifacts
- `expected/`: per-sample expected outcomes used by validation
- `splits/`: curated subsets such as `gold` and `clustering`
- `redirect-fixtures.json`: deterministic redirect chains for validation
- `manifest.json`: generated sample index with hashes and expectations
- `manifest.schema.json`: JSON Schema for the generated manifest

## Commands

Generate or refresh the scaffolded corpus:

```bash
python3 backend/scripts/generate_synthetic_corpus.py
```

Validate the generated corpus against the manifest:

```bash
python3 backend/scripts/validate_synthetic_corpus.py
```

Run the gold-split ingest regression inside the backend dependency environment:

```bash
cd backend
python -m unittest tests.test_synthetic_corpus_ingest
```

Import the gold split into a local demo stack on demand:

```bash
make import-synthetic SPLIT=gold
```

Leave imported cases open instead of auto-resolving them:

```bash
make import-synthetic SPLIT=gold OPEN_ONLY=1
```

Refresh already imported synthetic cases in place after the corpus or importer changes:

```bash
make import-synthetic SPLIT=gold REFRESH_EXISTING=1
```

Remove previously imported synthetic cases from a split:

```bash
make remove-synthetic SPLIT=gold
```

## Design Constraints

- Use only reserved example domains such as `example.com` and `example.net`
- Use only reserved documentation IP ranges such as `198.51.100.0/24`
- Keep attachment payloads inert and safe to store in the repository
- Keep redirect resolution deterministic; do not rely on live internet lookups
- Prefer `.eml` as the canonical format; add `.msg` later for parser coverage

## Current Scope

The initial scaffold ships a `gold` subset of twelve canonical samples covering:

- credential-harvest links
- shortener and redirect chains
- spoofing and BEC-style reply mismatches
- compromised sender scenarios
- malicious attachment delivery
- QR-assisted login lures
- callback fraud
- thread hijack patterns
- benign external and internal controls

The intent is to provide a stable baseline for CI and demos now, while leaving
room for a larger generated `scale` split later.
