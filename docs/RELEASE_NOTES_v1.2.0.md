# VulnAgent AI v1.2.0 — Initial public portfolio release

## Summary

Read-only vulnerability triage MVP combining Python, FastAPI, a three-stage LangGraph workflow, public threat intelligence and Mistral-assisted structured remediation recommendations.

## Included

- Nessus-style CSV ingestion and validation
- FIRST EPSS and CISA KEV enrichment for valid CVEs in live mode
- Transparent deterministic prioritization with severity, EPSS and KEV signals
- Three LangGraph stages: threat intelligence, risk prioritization and remediation
- Structured AI outputs with assessment, evidence, uncertainty, actions and validation steps
- Explicit fallback behavior when the model is unavailable
- Human review required; no automatic scanning, exploitation or patching
- Synthetic lab data and publicly documented CVE examples on simulated hosts
- README architecture diagram, screenshots and local setup instructions

## Known limitations

- Local demo only; no authentication, tenant isolation or persistent storage
- Fixed LangGraph workflow, not an autonomous multi-agent planner
- No embedding-based RAG, benchmarked agent evaluation or autonomous tool selection
- Risk score is illustrative and can saturate at 100
- External model and intelligence availability depend on APIs and rate limits
- Public CVE status does not establish vulnerability on a specific host

## Verification before tagging

Run `python -m pytest -q` locally; test both sample files and confirm Mistral response attribution versus deterministic fallback. Verify no `.env`, credentials, local data or virtual environment are tracked.

## Release tag

`v1.2.0`
