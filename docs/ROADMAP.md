# Roadmap

Triagent is being shaped into a focused, local-first phishing triage tool. The near-term direction is intentionally practical: make suspicious email investigation faster, clearer, and easier to document.

## Now

- Polish the public repository and documentation.
- Keep the analyst workspace compact, readable, and demo-ready.
- Preserve on-prem defaults and avoid mandatory third-party services.
- Improve report evidence exports so they are readable and compliance-friendly.

## Next

- URL normalization and redirect handling:
  - expand shortened URLs
  - preserve redirect chains
  - show original URL, resolved URL, final URL, and landing domain
  - flag suspicious destination shifts
- Attachment analysis workflow:
  - improve analyst handoff for isolated sandbox review
  - keep attachment names and hashes first-class artifacts
  - add integration points for internal sandbox systems without forcing cloud detonation
- Investigation bundle:
  - normalized JSON output
  - Markdown evidence package
  - IOC export
  - ATT&CK-style labels where useful
- Outlook add-in hardening:
  - clearer submission states
  - better error handling
  - deployment notes for self-hosted environments

## Later

- Local-first CLI/library extraction for fast offline analysis.
- Redirect-chain and landing-page enrichment with strict network controls.
- Sandbox connector interface for on-prem tools.
- More complete enterprise deployment guidance.
- Deeper IAM support beyond the initial LDAP integration.

## Non-Goals For The Prototype

- full SIEM replacement
- fully automated verdicts without analyst review
- cloud-only enrichment requirements
- broad case management or collaboration suite
- storing real customer phishing samples in this public repository
