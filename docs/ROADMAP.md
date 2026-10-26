# Engineering roadmap

These are **planned** improvements, not current features.

## Next: more discriminating risk prioritization
- Incorporate verified asset criticality and internet exposure where supplied.
- Preserve the raw score and components instead of saturating multiple findings at 100.
- Unit-test missing intelligence and contradictory signals.

## Next: source-grounded recommendations
- Retrieve vendor advisories and trusted remediation documents.
- Attach source provenance and timestamps to model context.
- Add evidence-grounding checks and uncertainty reporting.

## Later: agentic orchestration
- Introduce conditional routing and bounded tool selection.
- Add timeouts, retries and rate-limit handling with clear diagnostics.
- Require explicit human approval before any future action-taking capability.

## Later: measurable evaluation
- Create a versioned golden dataset of synthetic vulnerability scenarios.
- Evaluate classification, evidence attribution, tool use and unsafe recommendations.
- Compare deterministic and model-assisted outputs; publish methodology and results.

## Production hardening (future)
- Authentication, RBAC, tenant isolation, storage, audit trails, observability and background jobs.
- Deployment review, security testing and privacy controls before handling customer data.
