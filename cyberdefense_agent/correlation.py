from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


ATTACK_CHAIN_WEIGHTS = {
    "port_scan": 1,
    "web_attack": 2,
    "brute_force": 2,
    "malware_indicator": 3,
    "data_exfiltration": 4,
}


@dataclass(frozen=True)
class Campaign:
    campaign_id: str
    summary: str
    severity: str
    score: int
    confidence: str
    relation_reasons: list[str]
    attack_types: list[str]
    affected_assets: list[str]
    source_ips: list[str]
    timeline: dict[str, str]
    incident_indexes: list[int]
    investigation_timeline: list[dict]
    analyst_assessment: dict

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "summary": self.summary,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "relation_reasons": self.relation_reasons,
            "attack_types": self.attack_types,
            "affected_assets": self.affected_assets,
            "source_ips": self.source_ips,
            "timeline": self.timeline,
            "incident_indexes": self.incident_indexes,
            "investigation_timeline": self.investigation_timeline,
            "analyst_assessment": self.analyst_assessment,
        }


class CampaignCorrelator:
    def __init__(self, window_minutes: int = 60) -> None:
        self.window = timedelta(minutes=window_minutes)

    def correlate(self, incidents: list) -> list[Campaign]:
        groups = self._group_related_incidents(incidents)
        campaign_groups = [group for group in groups if len(group) >= 2]
        campaigns = [
            self._build_campaign(index, group)
            for index, group in enumerate(campaign_groups, start=1)
        ]
        campaigns.sort(key=lambda campaign: campaign.score, reverse=True)
        return campaigns

    def _group_related_incidents(self, incidents: list) -> list[list[tuple[int, object]]]:
        groups: list[list[tuple[int, object]]] = []
        for index, incident in enumerate(incidents, start=1):
            for group in groups:
                if self._is_related(incident, [item for _, item in group]):
                    group.append((index, incident))
                    break
            else:
                groups.append([(index, incident)])
        return groups

    def _is_related(self, incident: object, group: list[object]) -> bool:
        return any(self._relation_reasons(incident, existing) for existing in group)

    def _relation_reasons(self, left: object, right: object) -> list[str]:
        if not self._within_window(left, right):
            return []
        reasons = []
        if set(left.affected_assets) & set(right.affected_assets):
            reasons.append("shared_asset")
        if set(left.source_ips) & set(right.source_ips):
            reasons.append("shared_source_ip")
        return reasons

    def _within_window(self, left: object, right: object) -> bool:
        left_start = _parse_timestamp(left.timeline["first_seen"])
        left_end = _parse_timestamp(left.timeline["last_seen"])
        right_start = _parse_timestamp(right.timeline["first_seen"])
        right_end = _parse_timestamp(right.timeline["last_seen"])
        if None in (left_start, left_end, right_start, right_end):
            return True
        return left_start <= right_end + self.window and right_start <= left_end + self.window

    def _build_campaign(
        self,
        campaign_number: int,
        group: list[tuple[int, object]],
    ) -> Campaign:
        incidents = [incident for _, incident in group]
        attack_types = sorted(
            {incident.detection.attack_type for incident in incidents},
            key=lambda attack_type: ATTACK_CHAIN_WEIGHTS.get(attack_type, 99),
        )
        score = min(
            100,
            max(incident.score for incident in incidents)
            + 6 * (len(attack_types) - 1)
            + self._chain_bonus(attack_types),
        )
        reasons = self._group_relation_reasons(incidents)
        assets = sorted({asset for incident in incidents for asset in incident.affected_assets})
        sources = sorted({source for incident in incidents for source in incident.source_ips})
        first_seen = min(incident.timeline["first_seen"] for incident in incidents)
        last_seen = max(incident.timeline["last_seen"] for incident in incidents)
        return Campaign(
            campaign_id=f"campaign-{campaign_number:03d}",
            summary=self._summary(attack_types, assets, sources),
            severity=self._severity(score),
            score=score,
            confidence=self._confidence(attack_types, reasons),
            relation_reasons=reasons,
            attack_types=attack_types,
            affected_assets=assets,
            source_ips=sources,
            timeline={"first_seen": first_seen, "last_seen": last_seen},
            incident_indexes=[index for index, _ in group],
            investigation_timeline=self._investigation_timeline(group),
            analyst_assessment=self._analyst_assessment(attack_types, reasons, assets, sources),
        )

    def _group_relation_reasons(self, incidents: list[object]) -> list[str]:
        reasons: set[str] = set()
        for left_index, left in enumerate(incidents):
            for right in incidents[left_index + 1 :]:
                reasons.update(self._relation_reasons(left, right))
        return sorted(reasons)

    def _chain_bonus(self, attack_types: list[str]) -> int:
        ordered = [ATTACK_CHAIN_WEIGHTS.get(attack_type, 99) for attack_type in attack_types]
        if len(ordered) >= 3 and ordered == sorted(ordered):
            return 10
        return 0

    def _summary(
        self,
        attack_types: list[str],
        assets: list[str],
        sources: list[str],
    ) -> str:
        return (
            f"Related activity across {len(attack_types)} attack types "
            f"({', '.join(attack_types)}) affecting {', '.join(assets)} "
            f"from {', '.join(sources)}."
        )

    def _severity(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def _confidence(self, attack_types: list[str], reasons: list[str]) -> str:
        if len(attack_types) >= 3 and len(reasons) >= 2:
            return "high"
        if len(attack_types) >= 2 and reasons:
            return "medium"
        return "low"

    def _investigation_timeline(self, group: list[tuple[int, object]]) -> list[dict]:
        steps = []
        for index, incident in group:
            steps.append(
                {
                    "timestamp": incident.timeline["first_seen"],
                    "incident_index": index,
                    "attack_type": incident.detection.attack_type,
                    "severity": incident.severity,
                    "assets": incident.affected_assets,
                    "sources": incident.source_ips,
                    "summary": incident.detection.summary,
                }
            )
        return sorted(steps, key=lambda step: step["timestamp"])

    def _analyst_assessment(
        self,
        attack_types: list[str],
        reasons: list[str],
        assets: list[str],
        sources: list[str],
    ) -> dict:
        missing_context = [
            "Confirm whether the sources are expected scanners or service accounts.",
            "Check whether any successful authentication or process execution followed the first signal.",
        ]
        if "data_exfiltration" in attack_types or "data_transfer_anomaly" in attack_types:
            missing_context.append("Validate destination ownership and business justification for transfer volume.")
        return {
            "why_it_matters": (
                f"Related activity spans {len(attack_types)} attack type(s) "
                f"against {', '.join(assets)} from {', '.join(sources)}."
            ),
            "supporting_evidence": [
                f"Correlation reason: {reason}" for reason in reasons
            ] or ["Multiple incidents occurred within the configured correlation window."],
            "likely_false_positive_causes": [
                "Approved vulnerability scanning",
                "Administrative maintenance",
                "Known automation or backup activity",
            ],
            "missing_context": missing_context,
            "next_question": "What changed on the affected asset immediately before and after this activity?",
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
