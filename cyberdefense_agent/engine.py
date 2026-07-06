from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .baseline import BaselineProfile
from .config import AgentConfig
from .correlation import Campaign, CampaignCorrelator
from .events import SecurityEvent
from .investigation import Investigation, build_investigation
from .playbooks import Playbook, playbook_for
from .response import ResponsePlan, build_response_plan
from .rules import Detection, Rule, default_rules
from .threat_intel import ThreatIntel


CRITICALITY_WEIGHT = {
    "low": 0,
    "medium": 8,
    "high": 16,
    "critical": 24,
}


@dataclass(frozen=True)
class Incident:
    detection: Detection
    playbook: Playbook
    response_plan: ResponsePlan
    investigation: Investigation
    score_adjustment: int = 0
    feedback_context: list[dict] | None = None
    entity_context: list[dict] | None = None

    @property
    def score(self) -> int:
        asset_weight = max(
            CRITICALITY_WEIGHT.get(event.asset_criticality, 0)
            for event in self.detection.evidence
        )
        return max(0, min(100, self.detection.base_score + asset_weight + self.score_adjustment))

    @property
    def severity(self) -> str:
        if self.score >= 80:
            return "critical"
        if self.score >= 60:
            return "high"
        if self.score >= 35:
            return "medium"
        return "low"

    @property
    def affected_assets(self) -> list[str]:
        return sorted({event.asset for event in self.detection.evidence})

    @property
    def source_ips(self) -> list[str]:
        return sorted({event.source_ip for event in self.detection.evidence})

    @property
    def timeline(self) -> dict[str, str]:
        timestamps = sorted(event.timestamp for event in self.detection.evidence)
        return {"first_seen": timestamps[0], "last_seen": timestamps[-1]}

    @property
    def risk_signals(self) -> list[dict[str, str]]:
        signals = []
        if any(event.asset_criticality == "critical" for event in self.detection.evidence):
            signals.append(
                {
                    "signal": "critical_asset",
                    "detail": "At least one affected asset is marked critical.",
                }
            )
        if len(self.detection.evidence) > 1:
            signals.append(
                {
                    "signal": "repeated_activity",
                    "detail": f"{len(self.detection.evidence)} related events support this incident.",
                }
            )
        if self.detection.attack_type in {"threat_intel_match", "data_exfiltration"}:
            signals.append(
                {
                    "signal": "high_impact_attack_type",
                    "detail": f"{self.detection.attack_type} is treated as high-impact activity.",
                }
            )
        if self.score_adjustment > 0:
            signals.append(
                {
                    "signal": "memory_score_increase",
                    "detail": "Stored memory increased this incident's score.",
                }
            )
        if self.score_adjustment < 0:
            signals.append(
                {
                    "signal": "memory_score_decrease",
                    "detail": "Stored memory decreased this incident's score.",
                }
            )
        for context in self.entity_context or []:
            signals.append(
                {
                    "signal": f"entity_{context['entity_type']}_history",
                    "detail": (
                        f"{context['value']} has {context['incident_count']} prior "
                        f"incident(s) across {context['case_count']} case(s)."
                    ),
                }
            )
        return signals

    def to_dict(self) -> dict:
        return {
            "attack_type": self.detection.attack_type,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.detection.confidence,
            "tactic": self.detection.tactic,
            "technique_id": self.detection.technique_id,
            "rule_name": self.detection.rule_name or self.detection.attack_type,
            "explanation": self.detection.explanation,
            "occurrence_count": len(self.detection.evidence),
            "score_adjustment": self.score_adjustment,
            "feedback_context": self.feedback_context or [],
            "entity_context": self.entity_context or [],
            "risk_signals": self.risk_signals,
            "summary": self.detection.summary,
            "affected_assets": self.affected_assets,
            "source_ips": self.source_ips,
            "timeline": self.timeline,
            "evidence": [event.to_dict() for event in self.detection.evidence],
            "recommended_actions": self.playbook.actions,
            "response_plan": self.response_plan.to_dict(),
            "investigation": self.investigation.to_dict(),
        }


@dataclass
class DefenseReport:
    incidents: list[Incident]
    campaigns: list[Campaign]
    memory: dict | None = None
    import_diagnostics: dict | None = None

    def to_dict(self) -> dict:
        return {
            "incident_count": len(self.incidents),
            "campaign_count": len(self.campaigns),
            "incidents": [incident.to_dict() for incident in self.incidents],
            "campaigns": [campaign.to_dict() for campaign in self.campaigns],
            "memory": self.memory or {},
            "import_diagnostics": self.import_diagnostics or {},
        }

    def render(self) -> str:
        import_lines = self._render_import_diagnostics()
        if not self.incidents:
            if import_lines:
                return "\n".join(["No incidents detected.", "", *import_lines])
            return "No incidents detected."

        lines = [f"Detected {len(self.incidents)} incident(s)."]
        if import_lines:
            lines.extend(["", *import_lines])
        if self.campaigns:
            lines.extend(["", f"Correlated {len(self.campaigns)} campaign(s)."])
            for campaign in self.campaigns:
                lines.extend(
                    [
                        f"   - {campaign.campaign_id}: {campaign.severity} "
                        f"({campaign.score}/100, {campaign.confidence} confidence)",
                        f"     {campaign.summary}",
                    ]
                )
        if self.memory:
            feedback_matches = self.memory.get("feedback_matches") or []
            lines.extend(
                [
                    "",
                    f"Memory: {self.memory.get('stored_incidents', 0)} stored incident(s).",
                ]
            )
            triage_counts = self.memory.get("triage_state_counts") or {}
            if triage_counts:
                summary = ", ".join(
                    f"{state}={count}" for state, count in sorted(triage_counts.items())
                )
                lines.append(f"Triage states: {summary}.")
            stored_ids = self.memory.get("last_stored_incident_ids") or []
            if stored_ids:
                lines.append(f"Stored incident IDs: {', '.join(map(str, stored_ids))}.")
            top_entities = self.memory.get("top_entities") or {}
            if any(top_entities.values()):
                lines.append("Entity profiles:")
                for entity_type, profiles in sorted(top_entities.items()):
                    if not profiles:
                        continue
                    summary = ", ".join(
                        f"{profile['value']}({profile['incident_count']} incidents)"
                        for profile in profiles[:3]
                    )
                    lines.append(f"   - {entity_type}: {summary}")
            if feedback_matches:
                lines.append("Feedback context:")
                for match in feedback_matches:
                    note = f" - {match['note']}" if match.get("note") else ""
                    lines.append(
                        f"   - {match['attack_type']}: prior "
                        f"{match['verdict']} on incident "
                        f"{match['matched_incident_id']}{note}"
                    )
        for index, incident in enumerate(self.incidents, start=1):
            lines.extend(
                [
                    "",
                    f"{index}. {incident.detection.attack_type.upper()}",
                    f"   Severity: {incident.severity} ({incident.score}/100)",
                    f"   Confidence: {incident.detection.confidence}",
                    f"   Technique: {incident.detection.technique_id} ({incident.detection.tactic})",
                    f"   Rule: {incident.detection.rule_name or incident.detection.attack_type}",
                    f"   Assets: {', '.join(incident.affected_assets)}",
                    f"   Sources: {', '.join(incident.source_ips)}",
                    f"   Occurrences: {len(incident.detection.evidence)}",
                    (
                        "   Timeline: "
                        f"{incident.timeline['first_seen']} to {incident.timeline['last_seen']}"
                    ),
                    f"   Summary: {incident.detection.summary}",
                    "   Recommended actions:",
                ]
            )
            investigation = incident.investigation.to_dict()
            lines.insert(-1, f"   Investigation: {investigation['why_it_matters']}")
            lines.insert(
                -1,
                "   Confidence after investigation: "
                f"{investigation['confidence_assessment']['adjusted_confidence']}",
            )
            lines.insert(
                -1,
                "   Response readiness: "
                f"{investigation['response_readiness']['overall_state']}",
            )
            if investigation["missing_context"]:
                lines.insert(
                    -1,
                    "   Missing context: "
                    f"{'; '.join(investigation['missing_context'][:3])}",
                )
            if incident.risk_signals:
                signals = ", ".join(signal["signal"] for signal in incident.risk_signals)
                lines.insert(-1, f"   Risk signals: {signals}")
            if incident.detection.explanation:
                why = ", ".join(
                    f"{key}={value}"
                    for key, value in incident.detection.explanation.items()
                )
                lines.insert(-1, f"   Why: {why}")
            if incident.score_adjustment:
                lines.insert(-1, f"   Memory score adjustment: {incident.score_adjustment:+d}")
            if incident.feedback_context:
                for context in incident.feedback_context:
                    note = f" - {context['note']}" if context.get("note") else ""
                    lines.insert(
                        -1,
                        "   Feedback match: "
                        f"{context['verdict']} on incident "
                        f"{context['matched_incident_id']}{note}",
                    )
            if incident.entity_context:
                for context in incident.entity_context:
                    lines.insert(
                        -1,
                        "   Entity memory: "
                        f"{context['entity_type']} {context['value']} "
                        f"({context['incident_count']} prior incident(s), "
                        f"{context['case_count']} case(s), {context['score_delta']:+d})",
                    )
            lines.extend(
                f"   - [{step.mode}] {step.action}"
                for step in incident.response_plan.steps
            )
        return "\n".join(lines)

    def _render_import_diagnostics(self) -> list[str]:
        diagnostics = self.import_diagnostics or {}
        skipped_count = diagnostics.get("skipped_count", 0)
        if not skipped_count:
            return []
        lines = [f"Import diagnostics: skipped {skipped_count} malformed record(s)."]
        for issue in (diagnostics.get("issues") or [])[:5]:
            lines.append(
                f"   - line {issue.get('line_number')}: {issue.get('message')}"
            )
        return lines


class DefenseAgent:
    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        extra_rules: Iterable[Rule] | None = None,
        config: AgentConfig | None = None,
        baseline: BaselineProfile | None = None,
        threat_intel: ThreatIntel | None = None,
    ) -> None:
        self.config = config or AgentConfig()
        self.baseline = baseline
        self.threat_intel = threat_intel
        self.rules = list(
            rules or default_rules(self.config, self.baseline, self.threat_intel)
        )
        self.rules.extend(extra_rules or [])
        self.correlator = CampaignCorrelator(
            window_minutes=self.config.correlation_window_minutes
        )

    def analyze(self, events: Iterable[SecurityEvent]) -> DefenseReport:
        event_list = list(events)
        incidents = [
            self._build_incident(detection, event_list)
            for rule in self.rules
            for detection in self._configured_detections(rule.detect(event_list))
            if not self._is_suppressed(detection)
        ]
        incidents = self._deduplicate(incidents)
        incidents.sort(key=lambda incident: incident.score, reverse=True)
        return DefenseReport(
            incidents=incidents,
            campaigns=self.correlator.correlate(incidents),
        )

    def _build_incident(
        self,
        detection: Detection,
        event_context: list[SecurityEvent] | None = None,
    ) -> Incident:
        playbook = playbook_for(detection.attack_type)
        response_plan = build_response_plan(playbook)
        return Incident(
            detection=detection,
            playbook=playbook,
            response_plan=response_plan,
            investigation=build_investigation(
                detection,
                response_plan,
                event_context or detection.evidence,
            ),
        )

    def _deduplicate(self, incidents: list[Incident]) -> list[Incident]:
        grouped: dict[tuple, list[Incident]] = {}
        for incident in incidents:
            key = (
                incident.detection.attack_type,
                incident.detection.rule_name,
                tuple(incident.affected_assets),
                tuple(incident.source_ips),
            )
            grouped.setdefault(key, []).append(incident)
        return [self._merge_incidents(group) for group in grouped.values()]

    def _merge_incidents(self, incidents: list[Incident]) -> Incident:
        if len(incidents) == 1:
            return incidents[0]
        primary = max(incidents, key=lambda incident: incident.detection.base_score)
        evidence = [
            event
            for incident in incidents
            for event in incident.detection.evidence
        ]
        explanation = dict(primary.detection.explanation)
        explanation["deduplicated_occurrences"] = len(incidents)
        merged_detection = replace(
            primary.detection,
            base_score=max(incident.detection.base_score for incident in incidents),
            evidence=evidence,
            summary=(
                f"{len(incidents)} related {primary.detection.attack_type} "
                f"detections affecting {', '.join(primary.affected_assets)}."
            ),
            explanation=explanation,
        )
        return self._build_incident(merged_detection, evidence)

    def _configured_detections(self, detections: Iterable[Detection]) -> list[Detection]:
        configured = []
        for detection in detections:
            identifiers = {
                detection.attack_type,
                detection.rule_name,
            }
            if identifiers & self.config.disabled_rules:
                continue
            override = self._score_override_for(detection)
            if override is not None:
                detection = replace(detection, base_score=override)
            configured.append(detection)
        return configured

    def _score_override_for(self, detection: Detection) -> int | None:
        overrides = self.config.rule_score_overrides
        if detection.attack_type in overrides:
            return overrides[detection.attack_type]
        if detection.rule_name in overrides:
            return overrides[detection.rule_name]
        return None

    def _is_suppressed(self, detection: Detection) -> bool:
        source_ips = {event.source_ip for event in detection.evidence}
        if source_ips & self.config.trusted_source_ips:
            return True
        if detection.attack_type == "port_scan" and source_ips & self.config.trusted_scanner_ips:
            return True
        return False
