from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


VALID_ENTITY_TYPES = {
    "source_ip",
    "asset",
    "user",
    "domain",
    "hash",
    "url",
}


@dataclass(frozen=True)
class EntityProfile:
    entity_type: str
    value: str
    incident_count: int = 0
    case_count: int = 0
    first_seen: str = "unknown"
    last_seen: str = "unknown"
    attack_types: dict[str, int] = field(default_factory=dict)
    severities: dict[str, int] = field(default_factory=dict)
    incident_ids: list[int] = field(default_factory=list)
    case_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "incident_count": self.incident_count,
            "case_count": self.case_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attack_types": self.attack_types,
            "severities": self.severities,
            "incident_ids": self.incident_ids,
            "case_ids": self.case_ids,
        }


class EntityStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def list_entities(
        self,
        entity_type: str,
        limit: int = 25,
    ) -> list[EntityProfile]:
        _validate_entity_type(entity_type)
        profiles = self._profiles(entity_type)
        profiles.sort(
            key=lambda profile: (profile.incident_count, profile.case_count, profile.last_seen),
            reverse=True,
        )
        return profiles[:limit]

    def get_entity(self, entity_type: str, value: str) -> EntityProfile:
        _validate_entity_type(entity_type)
        normalized = _normalize_value(value)
        for profile in self._profiles(entity_type):
            if profile.value == normalized:
                return profile
        return EntityProfile(entity_type=entity_type, value=normalized)

    def _profiles(self, entity_type: str) -> list[EntityProfile]:
        profiles: dict[str, dict[str, Any]] = {}
        with sqlite3.connect(self.path) as connection:
            incident_rows = connection.execute(
                """
                SELECT id, attack_type, severity, first_seen, last_seen, payload_json
                FROM incidents
                ORDER BY id
                """
            ).fetchall()
            case_ids_by_incident = _case_ids_by_incident(connection)

        for incident_id, attack_type, severity, first_seen, last_seen, raw_payload in incident_rows:
            try:
                payload = json.loads(raw_payload)
            except json.JSONDecodeError:
                payload = {}
            for value in _entity_values(entity_type, payload):
                profile = profiles.setdefault(value, _empty_profile(entity_type, value))
                profile["incident_ids"].add(incident_id)
                profile["case_ids"].update(case_ids_by_incident.get(incident_id, set()))
                profile["attack_types"][attack_type] = profile["attack_types"].get(attack_type, 0) + 1
                profile["severities"][severity] = profile["severities"].get(severity, 0) + 1
                profile["first_seen"] = _earliest(profile["first_seen"], first_seen)
                profile["last_seen"] = _latest(profile["last_seen"], last_seen)

        return [
            EntityProfile(
                entity_type=entity_type,
                value=value,
                incident_count=len(raw["incident_ids"]),
                case_count=len(raw["case_ids"]),
                first_seen=raw["first_seen"],
                last_seen=raw["last_seen"],
                attack_types=dict(sorted(raw["attack_types"].items())),
                severities=dict(sorted(raw["severities"].items())),
                incident_ids=sorted(raw["incident_ids"]),
                case_ids=sorted(raw["case_ids"]),
            )
            for value, raw in profiles.items()
        ]


def top_entity_summary(path: Path, limit: int = 5) -> dict[str, list[dict]]:
    store = EntityStore(path)
    summary: dict[str, list[dict]] = {}
    for entity_type in ("source_ip", "asset", "user"):
        summary[entity_type] = [
            {
                "value": profile.value,
                "incident_count": profile.incident_count,
                "case_count": profile.case_count,
                "last_seen": profile.last_seen,
            }
            for profile in store.list_entities(entity_type, limit=limit)
        ]
    return summary


def _case_ids_by_incident(connection: sqlite3.Connection) -> dict[int, set[int]]:
    mapping: dict[int, set[int]] = {}
    rows = connection.execute("SELECT id, incident_ids FROM cases").fetchall()
    for case_id, raw_incident_ids in rows:
        try:
            incident_ids = json.loads(raw_incident_ids)
        except json.JSONDecodeError:
            incident_ids = []
        for incident_id in incident_ids:
            mapping.setdefault(int(incident_id), set()).add(case_id)
    return mapping


def _entity_values(entity_type: str, payload: dict) -> set[str]:
    values: set[str] = set()
    if entity_type == "source_ip":
        values.update(payload.get("source_ips") or [])
    elif entity_type == "asset":
        values.update(payload.get("affected_assets") or [])
    for event in payload.get("evidence") or []:
        details = event.get("details") or {}
        if entity_type == "user":
            values.add(event.get("username", ""))
        elif entity_type == "domain":
            values.update(
                str(details.get(key, ""))
                for key in ("domain", "host", "hostname", "request_host", "sni")
            )
        elif entity_type == "hash":
            values.update(
                str(details.get(key, ""))
                for key in ("hash", "file_hash", "sha256", "md5")
            )
        elif entity_type == "url":
            values.update(str(details.get(key, "")) for key in ("url", "uri", "path"))
    return {
        normalized
        for value in values
        if (normalized := _normalize_value(value)) and normalized != "unknown"
    }


def _empty_profile(entity_type: str, value: str) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "value": value,
        "incident_ids": set(),
        "case_ids": set(),
        "first_seen": "unknown",
        "last_seen": "unknown",
        "attack_types": {},
        "severities": {},
    }


def _validate_entity_type(entity_type: str) -> None:
    if entity_type not in VALID_ENTITY_TYPES:
        allowed = ", ".join(sorted(VALID_ENTITY_TYPES))
        raise ValueError(f"Invalid entity type '{entity_type}'. Expected one of: {allowed}")


def _normalize_value(value: object) -> str:
    return str(value or "").strip().lower()


def _earliest(current: str, candidate: str) -> str:
    if current == "unknown":
        return candidate
    if candidate == "unknown":
        return current
    return min(current, candidate)


def _latest(current: str, candidate: str) -> str:
    if current == "unknown":
        return candidate
    if candidate == "unknown":
        return current
    return max(current, candidate)
