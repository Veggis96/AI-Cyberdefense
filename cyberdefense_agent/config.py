from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AgentConfig:
    brute_force_threshold: int = 5
    port_scan_threshold: int = 8
    exfiltration_bytes_threshold: int = 100_000_000
    correlation_window_minutes: int = 60
    trusted_scanner_ips: set[str] = field(default_factory=set)
    trusted_source_ips: set[str] = field(default_factory=set)
    disabled_rules: set[str] = field(default_factory=set)
    rule_score_overrides: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentConfig":
        thresholds = dict(raw.get("thresholds") or {})
        correlation = dict(raw.get("correlation") or {})
        allowlists = dict(raw.get("allowlists") or {})
        rules = dict(raw.get("rules") or {})
        return cls(
            brute_force_threshold=int(thresholds.get("brute_force_failures", 5)),
            port_scan_threshold=int(thresholds.get("port_scan_ports", 8)),
            exfiltration_bytes_threshold=int(
                thresholds.get("exfiltration_bytes", 100_000_000)
            ),
            correlation_window_minutes=int(correlation.get("window_minutes", 60)),
            trusted_scanner_ips=set(allowlists.get("trusted_scanner_ips") or []),
            trusted_source_ips=set(allowlists.get("trusted_source_ips") or []),
            disabled_rules={str(rule) for rule in rules.get("disabled", [])},
            rule_score_overrides={
                str(rule): int(score)
                for rule, score in dict(rules.get("score_overrides") or {}).items()
            },
        )


def load_config(path: Path | None) -> AgentConfig:
    if path is None:
        return AgentConfig()
    with path.open("r", encoding="utf-8") as handle:
        return AgentConfig.from_dict(json.load(handle))
