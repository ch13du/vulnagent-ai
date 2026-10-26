# VulnAgent AI 🛡️

**Python + LangGraph + Mistral | Read-only vulnerability triage MVP**

Upload a Nessus-style CSV to review vulnerability severity, optional live EPSS and CISA KEV signals, and AI-assisted remediation recommendations. The dashboard displays a three-stage LangGraph execution trace and source-linked evidence.

## Run locally (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` with your Mistral key and model. The app does not automatically read `.env`.

```powershell
Get-Content .env | ForEach-Object { if ($_ -match '^\s*(MISTRAL_API_KEY|MISTRAL_MODEL)\s*=\s*(.+?)\s*$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim().Trim('"').Trim("'"), 'Process') } }
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 and upload `samples/nessus_demo.csv`. The API is documented at `/docs`.

## Tests

```powershell
python -m pytest -q
```

## Architecture

`Nessus CSV → validation → LangGraph threat intelligence → deterministic priority score → Mistral remediation guidance → human review`

The workflow has three fixed LangGraph nodes: `threat_intelligence`, `risk_prioritization`, and `remediation_agent`. It is **not** an autonomous multi-agent system or vector-based RAG implementation.

## Prioritization

`min(100, severity_level × 20 + round(20 × EPSS) + (20 if listed in CISA KEV else 0))`

This is an illustrative heuristic, not CVSS or a calibrated probability of compromise. Missing EPSS/KEV data means **unknown**, not safe. A CVE identifier in the CSV is unverified until validated against the actual asset.

## Safety, limitations and privacy

- Read-only: no scanning, exploitation, patching or remote execution.
- Use only synthetic or explicitly authorized findings. Live mode sends findings to Mistral and CVE IDs to FIRST EPSS and downloads CISA KEV.
- Evidence is labeled verified only when an external response was successfully retrieved; this does not validate asset applicability.
- Human approval is required for any remediation. Scan content is untrusted input.
- No authentication, persistence, or multi-tenant security: run locally, not as a public service.
- Live AI calls can fail due to API quotas or networking, in which case deterministic guidance is shown.
- Recommendations are limited to the top 10 ranked findings.

## GitHub

Review `git status` before committing. `.env`, `.venv`, credentials and sensitive scans must never be committed.


## v1.0 showcase

- Responsive structured remediation panels, separated into model-produced sections.
- Three-stage LangGraph execution trace with completion/fallback state. These are **workflow nodes**, not autonomous agents with independent tool selection.
- FIRST EPSS and CISA KEV lookup for valid CVE identifiers in live mode. A CVE identifier alone does **not** prove that a given asset is vulnerable.
- `samples/public_cve_lab.csv` uses historically documented CVE IDs attached to **synthetic assets**. It does not establish applicability.
- All remediation is read-only and requires human review.
- Mistral outputs are model-generated advice, not independently validated remediation.

### Security / privacy
Never upload customer scans without permission. Live mode transmits findings to the configured model provider and retrieves public intelligence. Do not commit `.env`, API keys, virtual environments or private scan data.

### Windows quickstart
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env to add MISTRAL_API_KEY and MISTRAL_MODEL=ministral-8b-2512
Get-Content .env | ForEach-Object { if ($_ -match '^\s*(MISTRAL_API_KEY|MISTRAL_MODEL)\s*=\s*(.+?)\s*$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim().Trim('"').Trim("'"), 'Process') } }
python -m pytest -q
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Choose Live for real Mistral and threat-intelligence requests.

## v1.1 dashboard polish

- Full-width, stacked AI report sections rather than narrow side-by-side text columns.
- Client-side Markdown presentation for headings, emphasis, numbered/bulleted lists, fenced code and tables, with HTML escaping and restricted external links.
- Improved spacing and typography; responsive layout remains available on mobile.
- No changes to the Mistral, EPSS, KEV or LangGraph processing logic.

The application intentionally retains unverified-finding warnings and does not execute remediation.

## v1.2 structured remediation UI

Mistral is prompted to return JSON fields (assessment, evidence_summary, uncertainty, recommended_actions, validation_steps). The server validates these fields and the dashboard renders each field as escaped text, rather than attempting to parse arbitrary Markdown. Live Mistral requests may time out or be rate limited; the UI labels deterministic fallbacks. Threat intelligence does not verify that a simulated asset is affected.
