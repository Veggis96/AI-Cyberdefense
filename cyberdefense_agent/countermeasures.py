from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CountermeasureProposal:
    action_type: str
    title: str
    description: str
    command_preview: str
    approval_state: str = "pending"
    execution_mode: str = "dry-run"
    readiness: str = "human_required"

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "title": self.title,
            "description": self.description,
            "command_preview": self.command_preview,
            "approval_state": self.approval_state,
            "execution_mode": self.execution_mode,
            "readiness": self.readiness,
        }


def proposals_for_incident(incident: dict) -> list[CountermeasureProposal]:
    proposals = [_ticket_proposal(incident), _siem_search_proposal(incident)]
    for step in incident.get("response_plan", []):
        if not step.get("requires_approval"):
            continue
        action = step["action"].lower()
        if "block" in action or "rate-limit" in action:
            proposals.extend(_network_control_proposals(incident, step["action"]))
        elif "isolate" in action:
            proposals.extend(_endpoint_isolation_proposals(incident, step["action"]))
        elif any(token in action for token in ("disable", "lock", "credential", "rotate", "remove", "revoke")):
            proposals.extend(_identity_control_proposals(incident, step["action"]))
        elif "restrict" in action:
            proposals.extend(_network_control_proposals(incident, step["action"]))
    return _with_readiness(_dedupe(proposals), incident)


def _ticket_proposal(incident: dict) -> CountermeasureProposal:
    return CountermeasureProposal(
        action_type="ticket",
        title=f"Create investigation ticket for {incident['attack_type']}",
        description="Create a human-owned investigation ticket with incident evidence.",
        command_preview=(
            "ticket create "
            f"--severity {incident['severity']} "
            f"--title \"{incident['attack_type']} on {', '.join(incident['affected_assets'])}\""
        ),
    )


def _siem_search_proposal(incident: dict) -> CountermeasureProposal:
    sources = " OR ".join(f"source_ip:{source}" for source in incident["source_ips"])
    assets = " OR ".join(f"asset:{asset}" for asset in incident["affected_assets"])
    query = " AND ".join(part for part in (sources, assets, f"attack_type:{incident['attack_type']}") if part)
    return CountermeasureProposal(
        action_type="siem_search",
        title=f"Hunt for related {incident['attack_type']} activity",
        description="Run a SIEM search for matching sources, assets, and attack type.",
        command_preview=f"siem search '{query}'",
    )


def _network_control_proposals(incident: dict, recommendation: str) -> list[CountermeasureProposal]:
    proposals = []
    for source in incident["source_ips"]:
        if source == "unknown":
            continue
        proposals.append(
            CountermeasureProposal(
                action_type="network_control",
                title=f"Review network control for {source}",
                description=recommendation,
                command_preview=f"firewall propose-block --source-ip {source} --reason \"{incident['attack_type']}\"",
            )
        )
    if incident["attack_type"] == "web_attack":
        proposals.append(
            CountermeasureProposal(
                action_type="waf_rule",
                title="Review WAF rule for suspicious payload",
                description="Prepare a WAF rule review using the observed web attack payload.",
                command_preview="waf propose-rule --match suspicious_payload --mode review-only",
            )
        )
    return proposals


def _endpoint_isolation_proposals(incident: dict, recommendation: str) -> list[CountermeasureProposal]:
    return [
        CountermeasureProposal(
            action_type="endpoint_isolation",
            title=f"Review endpoint isolation for {asset}",
            description=recommendation,
            command_preview=f"edr propose-isolation --asset {asset} --mode approval-required",
        )
        for asset in incident["affected_assets"]
        if asset != "unknown"
    ]


def _identity_control_proposals(incident: dict, recommendation: str) -> list[CountermeasureProposal]:
    users = sorted(
        {
            evidence.get("username", "unknown")
            for evidence in incident.get("evidence", [])
            if evidence.get("username") not in (None, "", "unknown")
        }
    )
    return [
        CountermeasureProposal(
            action_type="identity_control",
            title=f"Review identity control for {user}",
            description=recommendation,
            command_preview=f"identity propose-review --user {user} --reason \"{incident['attack_type']}\"",
        )
        for user in users
    ]


def _dedupe(proposals: list[CountermeasureProposal]) -> list[CountermeasureProposal]:
    seen = set()
    unique = []
    for proposal in proposals:
        key = (proposal.action_type, proposal.command_preview)
        if key in seen:
            continue
        seen.add(key)
        unique.append(proposal)
    return unique


def _with_readiness(
    proposals: list[CountermeasureProposal],
    incident: dict,
) -> list[CountermeasureProposal]:
    readiness = (
        incident.get("investigation", {})
        .get("response_readiness", {})
        .get("overall_state", "human_required")
    )
    return [
        CountermeasureProposal(
            action_type=proposal.action_type,
            title=proposal.title,
            description=proposal.description,
            command_preview=proposal.command_preview,
            approval_state=proposal.approval_state,
            execution_mode=proposal.execution_mode,
            readiness=readiness,
        )
        for proposal in proposals
    ]
