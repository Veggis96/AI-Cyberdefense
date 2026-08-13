# MVP Definition

AI Cyberdefense Agent is an installable, local-first defensive analysis CLI.

## Goal

Help an analyst turn exported security logs into prioritized, explainable incidents with dry-run response guidance.

## Supported In MVP

- Local CLI execution through `cyberdefense-agent` or `py -m cyberdefense_agent`.
- Read-only input validation with parser diagnostics and normalized field coverage.
- Event ingestion for JSONL, CSV, nginx access logs, AWS CloudTrail, Azure AD, Okta, and Microsoft 365 audit logs.
- Normalization into one event model.
- Built-in detections for brute force, port scans, malware indicators, data exfiltration, web attack probes, and high-signal cloud or identity activity.
- Optional bundled and local YAML/JSON rule packs.
- Incident scoring by rule severity, confidence, asset criticality, memory context, and entity history.
- Correlation into campaign-level findings.
- SQLite-backed incident memory, feedback, triage state, cases, approvals, and entity profiles.
- Static HTML reports and JSON/Markdown response handoff bundles.
- Watch mode for repeated local analysis of a growing event file.

## Explicitly Out Of Scope

- Executing firewall, endpoint, identity, WAF, SIEM, or ticketing actions.
- Production API integrations.
- Hosted multi-user dashboard.
- Authentication, authorization, or tenant isolation.
- Real-time streaming ingestion from live production systems.

## Safety Boundary

All response actions are dry-run recommendations. Approval commands record analyst decisions and export handoff material, but they do not execute containment commands.

## Demo Path

From the project root:

```powershell
python -m pip install -e .
cyberdefense-agent demo
```

Generated artifacts:

- `reports/report.html`
- `reports/response.json`
- `data/incidents.sqlite`

## Pipeline

1. Parse source logs and collect import diagnostics.
2. Normalize records into `SecurityEvent`.
3. Run built-in, bundled, and local rules.
4. Suppress allowlisted or known-good activity.
5. Score, enrich, and deduplicate incidents.
6. Apply memory, feedback, and entity profile context when enabled.
7. Correlate incidents into campaigns.
8. Build investigation prompts, confidence review, response readiness, and dry-run response plans.
9. Persist optional memory objects.
10. Emit text, JSON, HTML, and response handoff outputs.

## Input Validation

Use validation before tuning detections or reviewing findings:

```powershell
cyberdefense-agent validate --events samples/events.jsonl
```

The command does not run detection rules or write memory. It reports which parser was selected, how many records were parsed or skipped, field coverage for normalized event attributes, event type distribution, top assets and source IPs, parse issues, and normalized samples.
