from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ThreatIndicator:
    value: str
    indicator_type: str
    threat: str
    confidence: str = "medium"
    source: str = "local"
    description: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ThreatIndicator":
        return cls(
            value=str(raw["value"]).lower(),
            indicator_type=str(raw["type"]).lower(),
            threat=str(raw.get("threat", "known threat")),
            confidence=str(raw.get("confidence", "medium")),
            source=str(raw.get("source", "local")),
            description=str(raw.get("description", "")),
        )


@dataclass(frozen=True)
class ThreatIntel:
    indicators: list[ThreatIndicator] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ThreatIntel":
        return cls(
            indicators=[
                ThreatIndicator.from_dict(item)
                for item in raw.get("indicators", [])
            ]
        )

    def match_event(self, event) -> list[ThreatIndicator]:
        values = _event_observables(event)
        return [
            indicator
            for indicator in self.indicators
            if indicator.value in values.get(indicator.indicator_type, set())
        ]


def load_threat_intel(path: Path | None) -> ThreatIntel | None:
    if path is None:
        return None
    with path.open("r", encoding="utf-8") as handle:
        return ThreatIntel.from_dict(json.load(handle))


def _event_observables(event) -> dict[str, set[str]]:
    details = event.details or {}
    domains = {
        str(details.get(key, "")).lower()
        for key in ("domain", "host", "hostname", "request_host", "sni")
        if details.get(key)
    }
    hashes = {
        str(details.get(key, "")).lower()
        for key in ("hash", "file_hash", "sha256", "md5")
        if details.get(key)
    }
    urls = {
        str(details.get(key, "")).lower()
        for key in ("url", "uri", "path")
        if details.get(key)
    }
    return {
        "ip": {event.source_ip.lower(), event.destination_ip.lower()},
        "domain": domains,
        "hash": hashes,
        "url": urls,
    }
