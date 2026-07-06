from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import unquote

from .baseline import BaselineProfile
from .config import AgentConfig
from .events import SecurityEvent
from .threat_intel import ThreatIntel


@dataclass(frozen=True)
class Detection:
    attack_type: str
    summary: str
    confidence: str
    base_score: int
    evidence: list[SecurityEvent]
    tactic: str
    technique_id: str
    rule_name: str = ""
    explanation: dict[str, Any] = field(default_factory=dict)


class Rule(Protocol):
    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        ...


class BruteForceRule:
    def __init__(self, threshold: int = 5) -> None:
        self.threshold = threshold

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        failures: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "auth_failure":
                failures[(event.source_ip, event.username)].append(event)

        detections = []
        for (source_ip, username), evidence in failures.items():
            if len(evidence) >= self.threshold:
                detections.append(
                    Detection(
                        attack_type="brute_force",
                        summary=(
                            f"{len(evidence)} failed logins for user {username} "
                            f"from {source_ip}."
                        ),
                        confidence="high",
                        base_score=62,
                        evidence=evidence,
                        tactic="credential_access",
                        technique_id="T1110",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "failed_login_count": len(evidence),
                            "threshold": self.threshold,
                            "source_ip": source_ip,
                            "username": username,
                        },
                    )
                )
        return detections


class PortScanRule:
    def __init__(self, threshold: int = 8) -> None:
        self.threshold = threshold

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        probes: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        seen_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        for event in events:
            if event.event_type != "network_connection":
                continue
            port = _safe_int((event.details or {}).get("destination_port"))
            if port is None:
                continue
            key = (event.source_ip, event.destination_ip)
            probes[key].append(event)
            seen_ports[key].add(port)

        detections = []
        for (source_ip, destination_ip), evidence in probes.items():
            port_count = len(seen_ports[(source_ip, destination_ip)])
            if port_count >= self.threshold:
                detections.append(
                    Detection(
                        attack_type="port_scan",
                        summary=(
                            f"{source_ip} contacted {port_count} distinct ports "
                            f"on {destination_ip}."
                        ),
                        confidence="medium",
                        base_score=46,
                        evidence=evidence,
                        tactic="discovery",
                        technique_id="T1046",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "distinct_port_count": port_count,
                            "threshold": self.threshold,
                            "source_ip": source_ip,
                            "destination_ip": destination_ip,
                        },
                    )
                )
        return detections


class MalwareIndicatorRule:
    suspicious_event_types = {"malware_alert", "suspicious_process", "edr_detection"}

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type in self.suspicious_event_types:
                indicator = (event.details or {}).get("indicator", event.event_type)
                detections.append(
                    Detection(
                        attack_type="malware_indicator",
                        summary=f"Malware-like activity on {event.asset}: {indicator}.",
                        confidence="high",
                        base_score=70,
                        evidence=[event],
                        tactic="execution",
                        technique_id="T1059",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "indicator": str(indicator),
                            "event_type": event.event_type,
                        },
                    )
                )
        return detections


class DataExfiltrationRule:
    def __init__(self, bytes_threshold: int = 100_000_000) -> None:
        self.bytes_threshold = bytes_threshold

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type != "data_transfer":
                continue
            details = event.details or {}
            bytes_out = _safe_int(details.get("bytes_out")) or 0
            destination_reputation = str(details.get("destination_reputation", "unknown"))
            if bytes_out >= self.bytes_threshold and destination_reputation == "unknown":
                detections.append(
                    Detection(
                        attack_type="data_exfiltration",
                        summary=(
                            f"{event.asset} sent {bytes_out} bytes to an unknown "
                            f"destination {event.destination_ip}."
                        ),
                        confidence="medium",
                        base_score=64,
                        evidence=[event],
                        tactic="exfiltration",
                        technique_id="T1041",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "bytes_out": bytes_out,
                            "threshold": self.bytes_threshold,
                            "destination_reputation": destination_reputation,
                        },
                    )
                )
        return detections


class WebAttackRule:
    suspicious_tokens = ("' or '1'='1", "../", "<script", "union select", "${jndi:")

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type != "http_request":
                continue
            path = unquote(str((event.details or {}).get("path", ""))).lower()
            if any(token in path for token in self.suspicious_tokens):
                detections.append(
                    Detection(
                        attack_type="web_attack",
                        summary=f"Suspicious web payload from {event.source_ip}: {path}",
                        confidence="medium",
                        base_score=52,
                        evidence=[event],
                        tactic="initial_access",
                        technique_id="T1190",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "matched_payload": path[:160],
                            "suspicious_tokens": list(self.suspicious_tokens),
                        },
                    )
                )
        return detections


class WindowsSecurityRule:
    suspicious_process_tokens = (
        " -enc ",
        " -encodedcommand ",
        "downloadstring",
        "invoke-webrequest",
        "iex ",
        "mimikatz",
        "rundll32",
        "regsvr32",
        "certutil",
    )

    event_detections = {
        "service_install": (
            "windows_service_install",
            "Service installation event on {asset}: {service_name}.",
            "persistence",
            "T1543.003",
            56,
        ),
        "audit_log_cleared": (
            "windows_audit_log_cleared",
            "Windows audit log was cleared on {asset}.",
            "defense_evasion",
            "T1070.001",
            74,
        ),
        "user_created": (
            "windows_user_created",
            "New Windows user account {target_username} was created on {asset}.",
            "persistence",
            "T1136.001",
            50,
        ),
        "privileged_logon": (
            "windows_privileged_logon",
            "Privileged Windows logon by {username} on {asset}.",
            "privilege_escalation",
            "T1078",
            44,
        ),
    }

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type == "process_creation":
                detection = self._detect_suspicious_process(event)
                if detection is not None:
                    detections.append(detection)
                continue

            mapped = self.event_detections.get(event.event_type)
            if mapped is None:
                continue
            attack_type, summary_template, tactic, technique_id, base_score = mapped
            detections.append(
                Detection(
                    attack_type=attack_type,
                    summary=summary_template.format(
                        asset=event.asset,
                        username=event.username,
                        target_username=self._detail(event, "target_username", event.username),
                        service_name=self._detail(event, "service_name", "unknown service"),
                    ),
                    confidence="medium",
                    base_score=base_score,
                    evidence=[event],
                    tactic=tactic,
                    technique_id=technique_id,
                    rule_name=self.__class__.__name__,
                    explanation={
                        "event_type": event.event_type,
                        **self._windows_context(event),
                    },
                )
            )
        return detections

    def _detect_suspicious_process(self, event: SecurityEvent) -> Detection | None:
        details = event.details or {}
        command_line = str(
            details.get("command_line")
            or details.get("process_name")
            or ""
        ).lower()
        if not any(token in f" {command_line} " for token in self.suspicious_process_tokens):
            return None
        return Detection(
            attack_type="windows_suspicious_process",
            summary=(
                f"Suspicious process command line on {event.asset}: "
                f"{command_line[:160]}"
            ),
            confidence="medium",
            base_score=66,
            evidence=[event],
            tactic="execution",
            technique_id="T1059",
            rule_name=self.__class__.__name__,
            explanation={
                "matched_command_line": command_line[:160],
                "process_name": str(details.get("process_name", "")),
                "parent_process_name": str(details.get("parent_process_name", "")),
                "suspicious_tokens": [
                    token.strip()
                    for token in self.suspicious_process_tokens
                    if token in f" {command_line} "
                ],
            },
        )

    def _windows_context(self, event: SecurityEvent) -> dict[str, str]:
        details = event.details or {}
        keys = (
            "subject_username",
            "target_username",
            "service_name",
            "service_file_name",
            "service_type",
            "process_name",
            "parent_process_name",
            "command_line",
        )
        return {key: str(details[key]) for key in keys if details.get(key)}

    def _detail(self, event: SecurityEvent, key: str, default: str) -> str:
        return str((event.details or {}).get(key) or default)


class RarePortRule:
    def __init__(self, baseline: BaselineProfile) -> None:
        self.baseline = baseline

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type != "network_connection":
                continue
            asset_baseline = self.baseline.assets.get(event.asset)
            if not asset_baseline or not asset_baseline.common_ports:
                continue
            port = _safe_int((event.details or {}).get("destination_port"))
            if port is not None and port not in asset_baseline.common_ports:
                detections.append(
                    Detection(
                        attack_type="rare_port_access",
                        summary=(
                            f"{event.asset} received traffic on rare port {port} "
                            f"from {event.source_ip}."
                        ),
                        confidence="medium",
                        base_score=38,
                        evidence=[event],
                        tactic="discovery",
                        technique_id="T1046",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "observed_port": port,
                            "common_ports": sorted(asset_baseline.common_ports),
                        },
                    )
                )
        return detections


class UnusualLoginHourRule:
    def __init__(self, baseline: BaselineProfile) -> None:
        self.baseline = baseline

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type != "auth_success":
                continue
            user_baseline = self.baseline.users.get(event.username)
            if not user_baseline or not user_baseline.login_hours:
                continue
            hour = _parse_hour(event.timestamp)
            if hour is not None and hour not in user_baseline.login_hours:
                detections.append(
                    Detection(
                        attack_type="unusual_login_time",
                        summary=(
                            f"User {event.username} logged in at unusual hour "
                            f"{hour:02d}:00 from {event.source_ip}."
                        ),
                        confidence="medium",
                        base_score=42,
                        evidence=[event],
                        tactic="defense_evasion",
                        technique_id="T1078",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "observed_hour": hour,
                            "expected_login_hours": sorted(user_baseline.login_hours),
                        },
                    )
                )
        return detections


class TransferSpikeRule:
    multiplier = 2

    def __init__(self, baseline: BaselineProfile) -> None:
        self.baseline = baseline

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if event.event_type != "data_transfer":
                continue
            asset_baseline = self.baseline.assets.get(event.asset)
            if not asset_baseline or asset_baseline.max_bytes_out is None:
                continue
            bytes_out = _safe_int((event.details or {}).get("bytes_out")) or 0
            threshold = asset_baseline.max_bytes_out * self.multiplier
            if bytes_out > threshold:
                detections.append(
                    Detection(
                        attack_type="data_transfer_anomaly",
                        summary=(
                            f"{event.asset} sent {bytes_out} bytes, above baseline "
                            f"threshold {threshold}."
                        ),
                        confidence="medium",
                        base_score=58,
                        evidence=[event],
                        tactic="exfiltration",
                        technique_id="T1041",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "bytes_out": bytes_out,
                            "threshold": threshold,
                            "baseline_max_bytes_out": asset_baseline.max_bytes_out,
                        },
                    )
                )
        return detections


class ThreatIntelRule:
    def __init__(self, threat_intel: ThreatIntel) -> None:
        self.threat_intel = threat_intel

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            for indicator in self.threat_intel.match_event(event):
                detections.append(
                    Detection(
                        attack_type="threat_intel_match",
                        summary=(
                            f"{indicator.indicator_type} indicator {indicator.value} "
                            f"matched {indicator.threat} from {indicator.source}."
                        ),
                        confidence=indicator.confidence,
                        base_score=72,
                        evidence=[event],
                        tactic="command_and_control",
                        technique_id="T1102",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "indicator_type": indicator.indicator_type,
                            "indicator_value": indicator.value,
                            "threat_source": indicator.source,
                        },
                    )
                )
        return detections


class CloudSaasRule:
    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        detections.extend(self._failed_login_spikes(events))
        for event in events:
            details = event.details or {}
            provider = str(details.get("provider", ""))
            event_name = str(details.get("event_name") or details.get("event_type") or details.get("operation") or "")
            if provider == "aws_cloudtrail" and event_name == "ConsoleLogin" and event.username == "root":
                detections.append(
                    self._single(
                        event,
                        "cloud_root_login",
                        "AWS root account console login observed.",
                        "initial_access",
                        "T1078.004",
                        78,
                        {"provider": provider, "event_name": event_name},
                    )
                )
            if provider == "aws_cloudtrail" and event_name == "CreateAccessKey":
                detections.append(
                    self._single(
                        event,
                        "cloud_access_key_created",
                        f"AWS access key was created by {event.username}.",
                        "persistence",
                        "T1098",
                        62,
                        {"provider": provider, "event_name": event_name},
                    )
                )
            if provider == "okta" and "user.mfa.factor" in event_name and "activate" in event_name:
                detections.append(
                    self._single(
                        event,
                        "saas_mfa_method_added",
                        f"Okta MFA factor was added or activated for {event.username}.",
                        "persistence",
                        "T1098",
                        48,
                        {"provider": provider, "event_type": event_name},
                    )
                )
            if provider == "okta" and "admin" in event_name and "grant" in event_name:
                detections.append(
                    self._single(
                        event,
                        "saas_admin_role_assignment",
                        f"Okta admin role assignment activity for {event.username}.",
                        "privilege_escalation",
                        "T1098",
                        64,
                        {"provider": provider, "event_type": event_name},
                    )
                )
            if provider == "m365" and event_name in {"Consent to application", "ConsentToApp"}:
                detections.append(
                    self._single(
                        event,
                        "saas_oauth_consent",
                        f"OAuth application consent activity by {event.username}.",
                        "persistence",
                        "T1528",
                        60,
                        {"provider": provider, "operation": event_name},
                    )
                )
        return detections

    def _failed_login_spikes(self, events: list[SecurityEvent]) -> list[Detection]:
        failures: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in events:
            provider = str((event.details or {}).get("provider", ""))
            if provider and event.event_type == "auth_failure":
                failures[(provider, event.username)].append(event)
        detections = []
        for (provider, username), evidence in failures.items():
            if len(evidence) >= 3:
                detections.append(
                    Detection(
                        attack_type="cloud_failed_login_spike",
                        summary=f"{len(evidence)} failed {provider} logins for {username}.",
                        confidence="medium",
                        base_score=54,
                        evidence=evidence,
                        tactic="credential_access",
                        technique_id="T1110",
                        rule_name=self.__class__.__name__,
                        explanation={
                            "provider": provider,
                            "username": username,
                            "failed_login_count": len(evidence),
                            "threshold": 3,
                        },
                    )
                )
        return detections

    def _single(
        self,
        event: SecurityEvent,
        attack_type: str,
        summary: str,
        tactic: str,
        technique_id: str,
        base_score: int,
        explanation: dict[str, Any],
    ) -> Detection:
        return Detection(
            attack_type=attack_type,
            summary=summary,
            confidence="medium",
            base_score=base_score,
            evidence=[event],
            tactic=tactic,
            technique_id=technique_id,
            rule_name=self.__class__.__name__,
            explanation=explanation,
        )


def default_rules(
    config: AgentConfig | None = None,
    baseline: BaselineProfile | None = None,
    threat_intel: ThreatIntel | None = None,
) -> list[Rule]:
    config = config or AgentConfig()
    rules: list[Rule] = [
        BruteForceRule(threshold=config.brute_force_threshold),
        PortScanRule(threshold=config.port_scan_threshold),
        MalwareIndicatorRule(),
        DataExfiltrationRule(bytes_threshold=config.exfiltration_bytes_threshold),
        WebAttackRule(),
        WindowsSecurityRule(),
        CloudSaasRule(),
    ]
    if baseline is not None:
        rules.extend(
            [
                RarePortRule(baseline),
                UnusualLoginHourRule(baseline),
                TransferSpikeRule(baseline),
            ]
        )
    if threat_intel is not None:
        rules.append(ThreatIntelRule(threat_intel))
    return rules


def _parse_hour(timestamp: str) -> int | None:
    if timestamp == "unknown":
        return None
    parsers = (
        lambda raw: datetime.fromisoformat(raw.replace("Z", "+00:00")),
        lambda raw: datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z"),
    )
    for parser in parsers:
        try:
            parsed = parser(timestamp)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.hour
        except ValueError:
            continue
    return None


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
