# Architecture and engineering decisions

## Data flow

1. `POST /analyze?mode=demo|live` receives a Nessus-style CSV upload.
2. `parse_csv` validates required columns, severity values, file size and a maximum of 300 findings.
3. LangGraph `threat_intelligence` optionally fetches FIRST EPSS and CISA KEV data for valid CVEs in live mode.
4. `risk_prioritization` computes a deterministic score and sorts findings.
5. `remediation_agent` asks Mistral for structured JSON for up to 10 findings, validates expected fields, and falls back when unavailable.
6. The dashboard displays priority, evidence, stage trace, source links, report sections and a human-approval reminder.

## Why these choices?

**Deterministic scoring:** repeatable and inspectable, but the current additive score saturates at 100 for multiple high-risk findings. It is not a probability or CVSS replacement.

**Structured model output:** five JSON fields avoid brittle Markdown parsing and support predictable UI components. The validator checks types and length, not the factual correctness of model claims.

**External threat intelligence:** EPSS estimates probability of exploitation in the wild; KEV indicates known exploitation. Neither establishes that a specific asset is vulnerable. Unavailable lookups are not treated as negative results.

**LangGraph:** gives explicit, inspectable workflow stages. The current graph is linear, with no autonomous planning or conditional tool choice. Future work may add decision nodes and approval checkpoints.

**Fail closed for actions:** the tool never patches, scans or executes commands. Remediation suggestions require human review.

## Threat model and trust boundaries

- **CSV inputs:** untrusted and potentially adversarial. Input size, column and value checks limit abuse but are not a complete security boundary.
- **External intelligence:** may be stale or unavailable. Display retrieval status and cite the retrieved source.
- **LLM:** receives untrusted scan fields as data, and its advice may be wrong. Structured response validation is not factual verification.
- **API key:** loaded from environment variables; never expose in the dashboard, repository or logs.
- **Deployment:** no authentication or tenant isolation; run only on a trusted local machine.

## Interfaces

- `GET /` — dashboard
- `GET /health` — health and whether a Mistral key is configured (not a live credential test)
- `POST /analyze?mode=demo|live` — analyze uploaded CSV
- `GET /docs` — FastAPI-generated API documentation

## Known limitations

No database or persistent audit trail; no user login; no RBAC; no multi-tenant isolation; no vector database or RAG; no independent vulnerability scanner; no asset verification; no autonomous remediation; no formal agent benchmark. Live calls are synchronous and may be slow for several findings.
