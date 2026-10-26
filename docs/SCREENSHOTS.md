# Screenshot guide

Create `docs/screenshots/` and add screenshots from **synthetic sample data only**.

Recommended screenshots:

1. `dashboard-overview.png` — header, summary metrics and workflow status.
2. `threat-intelligence.png` — one finding with EPSS/KEV source evidence and a simulated-asset disclaimer.
3. `structured-remediation.png` — assessment, evidence, uncertainty, actions and validation sections with the model label visible.

Capture at a readable browser width. Hide the Windows username, terminal environment, API keys and any private information. Do not label a screenshot as a live AI result if it shows deterministic fallback.

After adding screenshots, insert the following lines into the README below **Example output**:

```markdown
![VulnAgent AI dashboard](docs/screenshots/dashboard-overview.png)
![Structured remediation](docs/screenshots/structured-remediation.png)
```
