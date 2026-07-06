from __future__ import annotations

import json
from pathlib import Path

from .countermeasures import proposals_for_incident


def write_response_bundle(report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _bundle_payload(report)
    if path.suffix.lower() == ".md":
        path.write_text(_render_markdown(payload), encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _bundle_payload(report) -> dict:
    incidents = [incident.to_dict() for incident in report.incidents]
    return {
        "mode": "dry-run",
        "safety_boundary": (
            "This bundle contains recommended response actions only. "
            "No firewall, endpoint, identity, or ticketing action was executed."
        ),
        "incident_count": len(incidents),
        "campaign_count": len(report.campaigns),
        "recommended_tickets": [_ticket_for(incident) for incident in incidents],
        "recommended_network_controls": _network_controls(incidents),
        "recommended_endpoint_controls": _endpoint_controls(incidents),
        "countermeasure_proposals": [
            proposal.to_dict()
            for incident in incidents
            for proposal in proposals_for_incident(incident)
        ],
    }


def _ticket_for(incident: dict) -> dict:
    return {
        "title": f"{incident['severity'].upper()} {incident['attack_type']} on "
        f"{', '.join(incident['affected_assets'])}",
        "severity": incident["severity"],
        "summary": incident["summary"],
        "assets": incident["affected_assets"],
        "sources": incident["source_ips"],
        "timeline": incident["timeline"],
        "rule_name": incident.get("rule_name", ""),
        "why": incident.get("explanation", {}),
        "investigation": incident.get("investigation", {}),
        "response_steps": incident["response_plan"],
    }


def _network_controls(incidents: list[dict]) -> list[dict]:
    controls = []
    for incident in incidents:
        for step in incident["response_plan"]:
            action = step["action"].lower()
            if not any(token in action for token in ("block", "rate-limit", "restrict outbound")):
                continue
            controls.append(
                {
                    "mode": "approval-required",
                    "attack_type": incident["attack_type"],
                    "source_ips": incident["source_ips"],
                    "affected_assets": incident["affected_assets"],
                    "recommendation": step["action"],
                }
            )
    return controls


def _endpoint_controls(incidents: list[dict]) -> list[dict]:
    controls = []
    for incident in incidents:
        for step in incident["response_plan"]:
            if "isolate" not in step["action"].lower() and "disable" not in step["action"].lower():
                continue
            controls.append(
                {
                    "mode": "approval-required",
                    "attack_type": incident["attack_type"],
                    "affected_assets": incident["affected_assets"],
                    "recommendation": step["action"],
                }
            )
    return controls


def _render_markdown(payload: dict) -> str:
    lines = [
        "# AI Cyberdefense Response Bundle",
        "",
        f"Mode: `{payload['mode']}`",
        "",
        payload["safety_boundary"],
        "",
        f"- Incidents: {payload['incident_count']}",
        f"- Campaigns: {payload['campaign_count']}",
        "",
        "## Recommended Tickets",
    ]
    for ticket in payload["recommended_tickets"]:
        lines.extend(
            [
                "",
                f"### {ticket['title']}",
                "",
                f"- Severity: {ticket['severity']}",
                f"- Assets: {', '.join(ticket['assets'])}",
                f"- Sources: {', '.join(ticket['sources'])}",
                f"- Rule: {ticket['rule_name']}",
                f"- Summary: {ticket['summary']}",
                f"- Investigation: {ticket['investigation'].get('why_it_matters', '')}",
                (
                    "- Response readiness: "
                    f"{ticket['investigation'].get('response_readiness', {}).get('overall_state', 'unknown')}"
                ),
                "- Response steps:",
            ]
        )
        lines.extend(f"  - {step['action']}" for step in ticket["response_steps"])
    lines.extend(["", "## Approval-Required Network Controls"])
    lines.extend(_control_lines(payload["recommended_network_controls"]))
    lines.extend(["", "## Approval-Required Endpoint Controls"])
    lines.extend(_control_lines(payload["recommended_endpoint_controls"]))
    lines.extend(["", "## Countermeasure Proposals"])
    if payload["countermeasure_proposals"]:
        for proposal in payload["countermeasure_proposals"]:
            lines.extend(
                [
                    f"- `{proposal['approval_state']}` {proposal['action_type']}: {proposal['title']}",
                    f"  - Readiness: `{proposal['readiness']}`",
                    f"  - {proposal['description']}",
                    f"  - `{proposal['command_preview']}`",
                ]
            )
    else:
        lines.append("No countermeasure proposals generated.")
    return "\n".join(lines) + "\n"


def _control_lines(controls: list[dict]) -> list[str]:
    if not controls:
        return ["", "No controls recommended."]
    lines = []
    for control in controls:
        assets = ", ".join(control.get("affected_assets") or [])
        sources = ", ".join(control.get("source_ips") or [])
        target = f"assets={assets}"
        if sources:
            target += f", sources={sources}"
        lines.append(f"- `{control['mode']}` {control['attack_type']}: {target}")
        lines.append(f"  - {control['recommendation']}")
    return lines
