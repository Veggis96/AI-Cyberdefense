from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    event_type: str
    source_ip: str = "unknown"
    destination_ip: str = "unknown"
    username: str = "unknown"
    asset: str = "unknown"
    asset_criticality: str = "low"
    details: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecurityEvent":
        return cls(
            timestamp=str(raw.get("timestamp", "unknown")),
            event_type=str(raw.get("event_type", "unknown")),
            source_ip=str(raw.get("source_ip", "unknown")),
            destination_ip=str(raw.get("destination_ip", "unknown")),
            username=str(raw.get("username", "unknown")),
            asset=str(raw.get("asset", "unknown")),
            asset_criticality=str(raw.get("asset_criticality", "low")).lower(),
            details=dict(raw.get("details") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "asset": self.asset,
            "asset_criticality": self.asset_criticality,
            "details": self.details or {},
        }


def load_events(path: Path) -> list[SecurityEvent]:
    from .parsers import parse_events

    return parse_events(path, source_format="jsonl")
