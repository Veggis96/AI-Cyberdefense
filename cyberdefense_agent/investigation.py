from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .events import SecurityEvent
from .response import ResponsePlan
from .rules import Detection


HIGH_SIGNAL_ATTACKS = {
    "cloud_root_login",
    "data_exfiltration",
    "threat_intel_match",
    "windows_audit_log_cleared",
}


@dataclass(frozen=True)
class Investigation:
    why_it_matters: str
    supporting_evidence: list[str]
    related_events: list[dict[str, Any]]
    analyst_questions: list[str]
    missing_context: list[str]
    confidence_assessment: dict[str, Any]
    response_readiness: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "why_it_matters": self.why_it_matters,
            "supporting_evidence": self.supporting_evidence,
            "related_events": self.related_events,
            "analyst_questions": self.analyst_questions,
            "missing_context": self.missing_context,
            "confidence_assessment": self.confidence_assessment,
            "response_readiness": self.response_readiness,
        }


def build_investigation(
    detection: Detection,
    response_plan: ResponsePlan,
    all_events: list[SecurityEvent],
) -> Investigation:
    evidence = detection.evidence
    related_events = _related_events(evidence, all_events)
    supporting_evidence = _supporting_evidence(detection, related_events)
    missing_context = _missing_context(detection)
    confidence = _confidence_assessment(detection, supporting_evidence, related_events)
    return Investigation(
        why_it_matters=_why_it_matters(detection),
        supporting_evidence=supporting_evidence,
        related_events=[_event_summary(event) for event in related_events[:5]],
        analyst_questions=_analyst_questions(detection),
        missing_context=missing_context,
        confidence_assessment=confidence,
        response_readiness=_response_readiness(
            detection,
            response_plan,
            confidence["adjusted_confidence"],
            missing_context,
        ),
    )


def _why_it_matters(detection: Detection) -> str:
    attack_type = detection.attack_type
    if attack_type == "brute_force":
        return "Repeated authentication failures can be an early sign of password guessing or credential stuffing."
    if attack_type == "cloud_root_login":
        return "Root cloud account activity is high-impact because it can bypass normal administrative boundaries."
    if attack_type == "cloud_access_key_created":
        return "New cloud access keys can create durable access that survives password changes."
    if attack_type in {"saas_mfa_method_added", "saas_admin_role_assignment", "saas_oauth_consent"}:
        return "Identity and SaaS control-plane changes can create persistence or privilege escalation."
    if attack_type in {"data_exfiltration", "data_transfer_anomaly"}:
        return "Unusual outbound data movement can indicate attempted theft or unauthorized transfer."
    if attack_type == "web_attack":
        return "Suspicious web payloads may be probing exploitable application paths."
    if attack_type.startswith("windows_"):
        return "Windows security events can expose persistence, privilege use, or defense evasion on endpoints."
    return f"{attack_type} requires review because it matched a defensive detection rule."


def _supporting_evidence(
    detection: Detection,
    related_events: list[SecurityEvent],
) -> list[str]:
    evidence = detection.evidence
    signals = [
        f"{len(evidence)} event(s) directly matched {detection.rule_name or detection.attack_type}.",
    ]
    if len(evidence) > 1:
        signals.append("Multiple related events support the same finding.")
    if related_events:
        signals.append(f"{len(related_events)} nearby event(s) share the same asset or source.")
    if any(event.asset_criticality in {"high", "critical"} for event in evidence):
        signals.append("At least one affected asset has high or critical business impact.")
    if detection.explanation:
        keys = ", ".join(sorted(detection.explanation.keys())[:4])
        signals.append(f"Rule explanation includes: {keys}.")
    return signals


def _analyst_questions(detection: Detection) -> list[str]:
    common = ["Is this activity expected for the affected user, source, asset, or service?"]
    attack_type = detection.attack_type
    if attack_type in {"brute_force", "cloud_failed_login_spike"}:
        return [
            "Was there a successful login from the same source after the failures?",
            "Is the targeted account privileged, stale, or missing MFA?",
            *common,
        ]
    if attack_type in {"cloud_root_login", "cloud_access_key_created"}:
        return [
            "Was this cloud control-plane action tied to an approved change?",
            "Were new keys, policies, roles, or sessions created nearby?",
            "Does the source IP match an expected administrator location?",
        ]
    if attack_type in {"saas_mfa_method_added", "saas_admin_role_assignment", "saas_oauth_consent"}:
        return [
            "Was the identity change requested by the account owner or administrator?",
            "Did the same user have recent failed logins or impossible-travel signals?",
            "Which application, role, or MFA factor was added?",
        ]
    if attack_type in {"data_exfiltration", "data_transfer_anomaly"}:
        return [
            "What data classification or business process explains the transfer?",
            "Who owns the destination and has it been seen before?",
            "Should outbound access be restricted while evidence is preserved?",
        ]
    if attack_type == "web_attack":
        return [
            "Did the application return an error, redirect, or suspicious response after the payload?",
            "Was the request blocked by WAF or application controls?",
            "Are there more requests from the same source in the same session?",
        ]
    return common


def _missing_context(detection: Detection) -> list[str]:
    attack_type = detection.attack_type
    missing = ["Raw log source and owner confirmation."]
    if attack_type in {"brute_force", "cloud_failed_login_spike"}:
        missing.extend(["Successful login follow-up.", "MFA status and account privilege level."])
    elif attack_type.startswith("cloud_") or attack_type.startswith("saas_"):
        missing.extend(["Change-ticket context.", "Administrator ownership and source-location context."])
    elif attack_type in {"data_exfiltration", "data_transfer_anomaly"}:
        missing.extend(["Destination ownership.", "Expected transfer baseline and data classification."])
    elif attack_type == "web_attack":
        missing.extend(["HTTP response status.", "WAF disposition and application error logs."])
    elif attack_type.startswith("windows_"):
        missing.extend(["Endpoint process tree.", "Change-management or admin-maintenance context."])
    return missing


def _confidence_assessment(
    detection: Detection,
    supporting_evidence: list[str],
    related_events: list[SecurityEvent],
) -> dict[str, Any]:
    confidence_order = ["low", "medium", "high"]
    current = detection.confidence if detection.confidence in confidence_order else "medium"
    index = confidence_order.index(current)
    reasons = []
    if detection.attack_type in HIGH_SIGNAL_ATTACKS:
        index = min(index + 1, len(confidence_order) - 1)
        reasons.append("High-impact attack type.")
    if len(detection.evidence) >= 3 or related_events:
        index = min(index + 1, len(confidence_order) - 1)
        reasons.append("Additional supporting or nearby evidence.")
    if not supporting_evidence:
        index = max(index - 1, 0)
        reasons.append("Limited supporting evidence.")
    return {
        "original_confidence": current,
        "adjusted_confidence": confidence_order[index],
        "reasons": reasons or ["Confidence unchanged after investigation review."],
    }


def _response_readiness(
    detection: Detection,
    response_plan: ResponsePlan,
    adjusted_confidence: str,
    missing_context: list[str],
) -> dict[str, Any]:
    step_states = []
    has_approval_step = False
    has_evidence_gap = bool(missing_context)
    for step in response_plan.steps:
        if step.requires_approval:
            state = "human_required"
            has_approval_step = True
        elif _needs_more_evidence(step.action) and adjusted_confidence != "high":
            state = "needs_more_evidence"
            has_evidence_gap = True
        else:
            state = "ready"
        step_states.append(
            {
                **step.to_dict(),
                "readiness": state,
            }
        )
    if has_approval_step:
        overall = "human_required"
        rationale = "At least one recommended response step requires explicit human approval."
    elif has_evidence_gap:
        overall = "needs_more_evidence"
        rationale = "The agent needs more context before recommending containment."
    else:
        overall = "ready"
        rationale = "Evidence-gathering and low-risk response steps are ready to hand off."
    return {
        "overall_state": overall,
        "rationale": rationale,
        "steps": step_states,
    }


def _needs_more_evidence(action: str) -> bool:
    action_lower = action.lower()
    return any(
        token in action_lower
        for token in ("confirm", "validate", "review", "check", "identify")
    )


def _related_events(
    evidence: list[SecurityEvent],
    all_events: list[SecurityEvent],
) -> list[SecurityEvent]:
    evidence_ids = {id(event) for event in evidence}
    assets = {event.asset for event in evidence if event.asset}
    sources = {event.source_ip for event in evidence if event.source_ip}
    evidence_times = [_parse_timestamp(event.timestamp) for event in evidence]
    evidence_times = [timestamp for timestamp in evidence_times if timestamp is not None]
    related = []
    for event in all_events:
        if id(event) in evidence_ids:
            continue
        if event.asset not in assets and event.source_ip not in sources:
            continue
        if evidence_times:
            event_time = _parse_timestamp(event.timestamp)
            if event_time is not None and not any(
                abs(event_time - evidence_time) <= timedelta(minutes=30)
                for evidence_time in evidence_times
            ):
                continue
        related.append(event)
    return sorted(related, key=lambda event: event.timestamp)


def _event_summary(event: SecurityEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "asset": event.asset,
        "source_ip": event.source_ip,
        "username": event.username,
        "details": {
            key: value
            for key, value in (event.details or {}).items()
            if key in {"event_name", "event_type", "operation", "path", "destination_port"}
        },
    }


def _parse_timestamp(value: str) -> datetime | None:
    if value == "unknown":
        return None
    parsers = (
        lambda raw: datetime.fromisoformat(raw.replace("Z", "+00:00")),
        lambda raw: datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z"),
    )
    for parser in parsers:
        try:
            parsed = parser(value)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    return None
