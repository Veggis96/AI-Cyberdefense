# AI Cyberdefense Agent

A lab-safe defensive agent that analyzes security events, detects likely attacks, and recommends containment actions.

This version focuses on blue-team workflows:

- Detect brute force login attempts, port scans, malware indicators, data exfiltration, web attack probes, and high-signal cloud/SaaS identity activity.
- Parse JSONL, CSV exports, nginx access logs, AWS CloudTrail, Azure AD, Okta, and Microsoft 365 audit logs into one normalized event model.
- Score each finding by severity, confidence, and asset criticality.
- Map incidents to defensive context such as tactic, technique ID, assets, sources, and timeline.
- Suppress known-good sources such as approved vulnerability scanners.
- Correlate related incidents into higher-level campaigns.
- Build campaign investigation timelines and analyst assessment prompts.
- Build incident-level investigation assessments with supporting evidence, missing context, analyst questions, confidence review, and response readiness.
- Persist incidents to SQLite memory for repeat-source and repeat-asset awareness.
- Build long-term entity profiles for sources, users, assets, domains, hashes, and URLs.
- Use entity profile history to adjust later incident scores and risk signals.
- Persist lightweight cases linked to stored incidents.
- Generate approval-gated countermeasure proposals for human review.
- Detect baseline anomalies such as rare ports, odd login hours, and transfer spikes.
- Enrich incidents with risk signals such as critical assets, repeated activity, and prior analyst feedback.
- Produce explainable incident reports with dry-run response plans.
- Run in dry-run mode by default. It does not block IPs, kill processes, or change firewall rules.

## Quick Start

```powershell
python -m cyberdefense_agent --events samples/events.jsonl
```

Parse real-ish logs:

```powershell
python -m cyberdefense_agent --events samples/nginx_access.log --format nginx
python -m cyberdefense_agent --events samples/windows_security.csv --format csv
python -m cyberdefense_agent --events samples/cloudtrail.json --format aws_cloudtrail
python -m cyberdefense_agent --events samples/azure_signins.json --format azure_ad
python -m cyberdefense_agent --events samples/okta_events.json --format okta
python -m cyberdefense_agent --events samples/m365_audit.json --format m365
```

Use a config file for thresholds and allowlists:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --config samples/config.json
```

Machine-readable output:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --json
```

JSON and dashboard incident records include `rule_name` and `explanation` fields so analysts can see the threshold, observed value, indicator, or event attribute that caused a rule to fire.

The CLI also reports import diagnostics. Malformed JSONL or nginx log lines are skipped, counted, and included under `import_diagnostics` in JSON output and in the HTML dashboard.

Store incidents in local memory:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --memory-db data/incidents.sqlite
```

Stored analyst feedback is used as context for later matching incidents. Prior `false_positive`, `benign`, or `expected` verdicts lower the later score, while prior `true_positive` verdicts raise it. The score adjustment and matched feedback are included in text, JSON, and dashboard-ready incident records.

Entity profile history also affects later incidents. Repeated source IPs, assets, or users add bounded score context and appear as `entity_*_history` risk signals.

Inspect entity profiles from memory:

```powershell
python -m cyberdefense_agent entity list --memory-db data/incidents.sqlite --type source_ip
python -m cyberdefense_agent entity show --memory-db data/incidents.sqlite --type asset --value fileserver-01
```

Use a baseline for anomaly detection:

```powershell
python -m cyberdefense_agent --events samples/baseline_events.jsonl --baseline samples/baseline.json
```

Use local threat intelligence:

```powershell
python -m cyberdefense_agent --events samples/threat_intel_events.jsonl --threat-intel samples/threat_intel.json
```

Record analyst feedback:

```powershell
python -m cyberdefense_agent feedback add --memory-db data/incidents.sqlite --incident-id 1 --verdict false_positive --note "Approved scanner"
python -m cyberdefense_agent feedback list --memory-db data/incidents.sqlite
```

Track incident triage state:

```powershell
python -m cyberdefense_agent triage list --memory-db data/incidents.sqlite
python -m cyberdefense_agent triage set --memory-db data/incidents.sqlite --incident-id 1 --state investigating --note "Checking owner context"
```

Track investigation cases created from stored reports:

```powershell
python -m cyberdefense_agent case list --memory-db data/incidents.sqlite
python -m cyberdefense_agent case set --memory-db data/incidents.sqlite --case-id 1 --state investigating --owner alice --priority high --note "Initial owner assigned"
```

Review countermeasure proposals:

```powershell
python -m cyberdefense_agent approvals list --memory-db data/incidents.sqlite --state pending
python -m cyberdefense_agent approvals approve --memory-db data/incidents.sqlite --approval-id 1 --by alice --note "Reviewed in SOC"
python -m cyberdefense_agent approvals reject --memory-db data/incidents.sqlite --approval-id 2 --by alice --note "Known scanner"
python -m cyberdefense_agent approvals export --memory-db data/incidents.sqlite --state approved --output reports/approved-actions.md
```

Generate a static dashboard:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --html-report reports/report.html
```

Load local JSON/YAML detection rules:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --rules samples/local_rules.yaml
```

Load bundled detection packs:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --rule-pack windows
python -m cyberdefense_agent --events samples/events.jsonl --rule-pack web
python -m cyberdefense_agent --events samples/events.jsonl --rule-pack identity --rule-pack network
python -m cyberdefense_agent rule-pack list
python -m cyberdefense_agent rule-pack show --name windows
```

Available packs are `windows`, `web`, `identity`, `network`, and `exfiltration`. Use `--json` with `rule-pack list` or `rule-pack show` for automation-friendly inventory output.

Built-in cloud/SaaS detections include AWS root console logins, AWS access key creation, cloud failed-login spikes, Okta MFA factor activation, Okta admin role assignment, and Microsoft 365 OAuth application consent.

Write a dry-run response handoff bundle for ticketing, chat, or firewall review:

```powershell
python -m cyberdefense_agent --events samples/events.jsonl --response-bundle reports/response.json
python -m cyberdefense_agent --events samples/events.jsonl --response-bundle reports/response.md
```

Response bundles include investigation rationale, readiness state, and countermeasure proposals such as ticket creation, SIEM searches, firewall review, WAF review, endpoint isolation review, and identity review. These are command previews only; approving a proposal records the human decision and still does not execute the command. Approved proposals can be exported as Markdown or JSON handoff files.

Run continuously against a growing event file:

```powershell
python -m cyberdefense_agent watch --events samples/events.jsonl --interval 5
python -m cyberdefense_agent watch --events samples/events.jsonl --watch-state data/watch-state.json
```

Watch mode persists incident fingerprints in a JSON state file, so restarting the watcher does not re-announce the same incidents. When reports are stored in SQLite memory, related activity is merged into existing open cases and duplicate pending approvals are suppressed.

Run tests:

```powershell
python -m unittest discover -s tests
```

## Event Format

The agent normalizes multiple input formats into one internal event model.

JSON Lines:

```json
{"timestamp":"2026-07-02T12:00:00Z","source_ip":"203.0.113.10","event_type":"auth_failure","username":"admin","asset":"vpn-01","asset_criticality":"high"}
```

CSV exports can use common field names such as `TimeCreated`, `EventID`, `IpAddress`, `AccountName`, and `Computer`. Windows Event ID `4625` is normalized to `auth_failure`, while `4624` is normalized to `auth_success`. The parser also recognizes high-signal Windows security events including `4688` process creation, `4672` privileged logon, `4720` user creation, `7045` service installation, and `1102` audit log cleared. Windows fields such as `CommandLine`, `NewProcessName`, `ParentProcessName`, `ServiceName`, `ServiceFileName`, `SubjectUserName`, and `TargetUserName` are preserved as canonical event details for rule explanations.

Nginx access logs are normalized to `http_request` events with request details under `details`.

## Baseline Format

```json
{
  "assets": {
    "web-01": {
      "common_ports": [80, 443],
      "max_bytes_out": 50000000
    }
  },
  "users": {
    "admin": {
      "login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16]
    }
  }
}
```

## Threat Intel Format

```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.200",
      "threat": "suspected exfiltration endpoint",
      "confidence": "high",
      "source": "local-lab-feed"
    }
  ]
}
```

Supported indicator types are `ip`, `domain`, `hash`, and `url`.

## Config Format

```json
{
  "thresholds": {
    "brute_force_failures": 5,
    "port_scan_ports": 8,
    "exfiltration_bytes": 100000000
  },
  "correlation": {
    "window_minutes": 60
  },
  "allowlists": {
    "trusted_scanner_ips": ["198.51.100.25"],
    "trusted_source_ips": []
  },
  "rules": {
    "disabled": ["port_scan"],
    "score_overrides": {
      "DataExfiltrationRule": 80
    }
  }
}
```

Rules can be referenced by attack type such as `port_scan` or by rule class name such as `DataExfiltrationRule`.

## Local Rule Format

Local rules extend the built-in detections without changing Python code. Rule files can be JSON or simple YAML:

```yaml
rules:
  - name: Suspicious Curl Download
    attack_type: suspicious_download
    event_type: process_creation
    tactic: execution
    technique_id: T1059
    confidence: medium
    base_score: 52
    summary: Suspicious curl execution on {asset}
    conditions:
      - field: details.command_line
        contains: curl
```

Supported condition operators are `equals`, `contains`, `regex`, and `min`.

Standalone Sigma-like YAML documents are also supported for a practical subset:

```yaml
title: Suspicious PowerShell Or Certutil
description: Suspicious process execution
tags: [attack.execution, attack.t1059]
level: high
detection:
  selection_powershell:
    EventID: 4688
    CommandLine|contains|all: [powershell, encodedcommand]
  selection_certutil:
    EventID: 4688
    Image|endswith: certutil.exe
  condition: selection_powershell or selection_certutil
```

Supported Sigma features include `EventID` mapping, field modifiers such as `|contains`, `|contains|all`, `|endswith`, and `|startswith`, and simple `selection1 or selection2` / `selection and not filter` conditions.

## Current Agent Loop

1. Ingest JSONL events.
2. Parse source-specific logs.
3. Normalize records into `SecurityEvent`.
4. Run detection rules.
5. Suppress known-good findings from config.
6. Deduplicate repeated findings with the same type, rule, source, and asset.
7. Enrich incidents with risk signals.
8. Apply feedback-aware and entity-aware memory context when memory is enabled.
9. Score and rank incidents.
10. Correlate related incidents into campaigns.
11. Build campaign investigation timelines and analyst assessments.
12. Attach defensive context and response actions.
13. Build incident investigation assessments, confidence review, missing-context prompts, and response readiness labels.
14. Generate approval-gated countermeasure proposals.
15. Optionally persist incident memory, update entity profiles, merge related cases, suppress duplicate approvals, and apply prior analyst feedback.
16. Optionally write an interactive HTML dashboard.
17. Optionally write a dry-run response handoff bundle.
18. Emit a human report or JSON for another system.

## Safety Boundary

This project is for defensive monitoring, analysis, and training. Response actions are recommendations unless you explicitly add an approved integration layer later. Approval commands record human decisions; they do not run firewall, endpoint, identity, WAF, SIEM, or ticketing commands.
