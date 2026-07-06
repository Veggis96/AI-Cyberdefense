from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path

from .approvals import ensure_approvals_schema
from .countermeasures import proposals_for_incident
from .entities import EntityStore, top_entity_summary


@dataclass(frozen=True)
class MemoryStats:
    stored_incidents: int
    repeat_source_ips: dict[str, int]
    repeat_assets: dict[str, int]
    last_stored_incident_ids: list[int]
    feedback_matches: list[dict]
    triage_state_counts: dict[str, int]
    last_stored_case_ids: list[int]
    last_stored_approval_ids: list[int]
    open_cases: int
    pending_approvals: int
    top_entities: dict[str, list[dict]]

    def to_dict(self) -> dict:
        return {
            "stored_incidents": self.stored_incidents,
            "repeat_source_ips": self.repeat_source_ips,
            "repeat_assets": self.repeat_assets,
            "last_stored_incident_ids": self.last_stored_incident_ids,
            "feedback_matches": self.feedback_matches,
            "triage_state_counts": self.triage_state_counts,
            "last_stored_case_ids": self.last_stored_case_ids,
            "last_stored_approval_ids": self.last_stored_approval_ids,
            "open_cases": self.open_cases,
            "pending_approvals": self.pending_approvals,
            "top_entities": self.top_entities,
        }


class IncidentMemory:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()
        self._last_stored_incident_ids: list[int] = []
        self._last_feedback_matches: list[dict] = []
        self._last_stored_case_ids: list[int] = []
        self._last_stored_approval_ids: list[int] = []

    def store_report(self, report) -> MemoryStats:
        self._last_stored_incident_ids = []
        self._last_stored_case_ids = []
        self._last_stored_approval_ids = []
        with sqlite3.connect(self.path) as connection:
            self._last_feedback_matches = self._feedback_matches(connection, report)
            report.incidents = [
                _incident_with_memory_context(
                    incident=incident,
                    feedback_matches=_matches_for_incident(
                        incident,
                        self._last_feedback_matches,
                    ),
                    entity_matches=_entity_matches_for_incident(self.path, incident),
                )
                for incident in report.incidents
            ]
            for incident in report.incidents:
                payload = incident.to_dict()
                cursor = connection.execute(
                    """
                    INSERT INTO incidents (
                        attack_type,
                        severity,
                        score,
                        first_seen,
                        last_seen,
                        source_ips,
                        affected_assets,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["attack_type"],
                        payload["severity"],
                        payload["score"],
                        payload["timeline"]["first_seen"],
                        payload["timeline"]["last_seen"],
                        json.dumps(payload["source_ips"]),
                        json.dumps(payload["affected_assets"]),
                        json.dumps(payload),
                    ),
                )
                self._last_stored_incident_ids.append(cursor.lastrowid)
            self._store_cases(connection, report)
            self._store_approvals(connection, report)
        return self.stats()

    def stats(self) -> MemoryStats:
        with sqlite3.connect(self.path) as connection:
            stored_incidents = connection.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0]
            source_ips = [
                source
                for (raw_sources,) in connection.execute("SELECT source_ips FROM incidents")
                for source in json.loads(raw_sources)
            ]
            assets = [
                asset
                for (raw_assets,) in connection.execute("SELECT affected_assets FROM incidents")
                for asset in json.loads(raw_assets)
            ]
            state_counts = {
                state: count
                for state, count in connection.execute(
                    """
                    SELECT state, COUNT(*)
                    FROM incidents
                    GROUP BY state
                    """
                )
            }
            open_cases = connection.execute(
                """
                SELECT COUNT(*)
                FROM cases
                WHERE state NOT IN ('resolved', 'closed')
                """
            ).fetchone()[0]
            pending_approvals = connection.execute(
                "SELECT COUNT(*) FROM approvals WHERE state = 'pending'"
            ).fetchone()[0]
        return MemoryStats(
            stored_incidents=stored_incidents,
            repeat_source_ips=_counts_over_one(source_ips),
            repeat_assets=_counts_over_one(assets),
            last_stored_incident_ids=self._last_stored_incident_ids,
            feedback_matches=self._last_feedback_matches,
            triage_state_counts=state_counts,
            last_stored_case_ids=self._last_stored_case_ids,
            last_stored_approval_ids=self._last_stored_approval_ids,
            open_cases=open_cases,
            pending_approvals=pending_approvals,
            top_entities=top_entity_summary(self.path),
        )

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source_ips TEXT NOT NULL,
                    affected_assets TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'new',
                    analyst_note TEXT NOT NULL DEFAULT ''
                )
                """
            )
            _ensure_column(
                connection,
                table="incidents",
                column="state",
                definition="TEXT NOT NULL DEFAULT 'new'",
            )
            _ensure_column(
                connection,
                table="incidents",
                column="analyst_note",
                definition="TEXT NOT NULL DEFAULT ''",
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents (attack_type)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents (state)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES incidents (id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_incident_id ON feedback (incident_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON feedback (verdict)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'new',
                    incident_ids TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_state ON cases (state)"
            )
            _ensure_column(
                connection,
                table="cases",
                column="owner",
                definition="TEXT NOT NULL DEFAULT ''",
            )
            _ensure_column(
                connection,
                table="cases",
                column="priority",
                definition="TEXT NOT NULL DEFAULT 'normal'",
            )
            _ensure_column(
                connection,
                table="cases",
                column="notes",
                definition="TEXT NOT NULL DEFAULT ''",
            )
            _ensure_column(
                connection,
                table="cases",
                column="history_json",
                definition="TEXT NOT NULL DEFAULT '[]'",
            )
            ensure_approvals_schema(connection)

    def _feedback_matches(self, connection: sqlite3.Connection, report) -> list[dict]:
        matches: list[dict] = []
        rows = connection.execute(
            """
            SELECT i.id, i.attack_type, i.source_ips, i.affected_assets, f.verdict, f.note
            FROM feedback f
            JOIN incidents i ON i.id = f.incident_id
            """
        ).fetchall()
        for incident in report.incidents:
            incident_sources = set(incident.source_ips)
            incident_assets = set(incident.affected_assets)
            for row in rows:
                incident_id, attack_type, raw_sources, raw_assets, verdict, note = row
                if attack_type != incident.detection.attack_type:
                    continue
                if incident_sources & set(json.loads(raw_sources)) or incident_assets & set(
                    json.loads(raw_assets)
                ):
                    matches.append(
                        {
                            "attack_type": attack_type,
                            "matched_incident_id": incident_id,
                            "verdict": verdict,
                            "note": note,
                            "source_ips": json.loads(raw_sources),
                            "affected_assets": json.loads(raw_assets),
                            "score_delta": _feedback_score_delta(verdict),
                        }
                    )
        return matches

    def _store_cases(self, connection: sqlite3.Connection, report) -> None:
        incident_id_by_index = {
            index: incident_id
            for index, incident_id in enumerate(self._last_stored_incident_ids, start=1)
        }
        case_payloads = []
        if report.campaigns:
            for campaign in report.campaigns:
                payload = campaign.to_dict()
                incident_ids = [
                    incident_id_by_index[index]
                    for index in campaign.incident_indexes
                    if index in incident_id_by_index
                ]
                case_payloads.append(
                    {
                        "title": campaign.summary,
                        "severity": campaign.severity,
                        "score": campaign.score,
                        "incident_ids": incident_ids,
                        "payload": {"type": "campaign", **payload},
                    }
                )
        else:
            for index, incident in enumerate(report.incidents, start=1):
                payload = incident.to_dict()
                case_payloads.append(
                    {
                        "title": payload["summary"],
                        "severity": payload["severity"],
                        "score": payload["score"],
                        "incident_ids": [incident_id_by_index[index]],
                        "payload": {"type": "incident", **payload},
                    }
                )
        for case in case_payloads:
            existing_case_id = _matching_open_case_id(connection, case["payload"])
            if existing_case_id is not None:
                _merge_case(connection, existing_case_id, case)
                self._last_stored_case_ids.append(existing_case_id)
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO cases (
                        title,
                        severity,
                        score,
                        incident_ids,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        case["title"],
                        case["severity"],
                        case["score"],
                        json.dumps(case["incident_ids"]),
                        json.dumps(case["payload"]),
                    ),
                )
                self._last_stored_case_ids.append(cursor.lastrowid)

    def _store_approvals(self, connection: sqlite3.Connection, report) -> None:
        case_id_by_incident_id = {}
        rows = connection.execute(
            """
            SELECT id, incident_ids
            FROM cases
            WHERE id IN ({})
            """.format(",".join("?" for _ in self._last_stored_case_ids) or "NULL"),
            tuple(self._last_stored_case_ids),
        ).fetchall()
        for case_id, raw_incident_ids in rows:
            for incident_id in json.loads(raw_incident_ids):
                case_id_by_incident_id[incident_id] = case_id

        for index, incident in enumerate(report.incidents, start=1):
            incident_id = self._last_stored_incident_ids[index - 1]
            case_id = case_id_by_incident_id.get(incident_id)
            for proposal in proposals_for_incident(incident.to_dict()):
                duplicate = connection.execute(
                    """
                    SELECT 1
                    FROM approvals
                    WHERE state = 'pending'
                      AND command_preview = ?
                      AND COALESCE(case_id, -1) = COALESCE(?, -1)
                    """,
                    (proposal.command_preview, case_id),
                ).fetchone()
                if duplicate:
                    continue
                cursor = connection.execute(
                    """
                    INSERT INTO approvals (
                        action_type,
                        title,
                        description,
                        command_preview,
                        incident_id,
                        case_id,
                        payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal.action_type,
                        proposal.title,
                        proposal.description,
                        proposal.command_preview,
                        incident_id,
                        case_id,
                        json.dumps(proposal.to_dict()),
                    ),
                )
                self._last_stored_approval_ids.append(cursor.lastrowid)


def _counts_over_one(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return {value: count for value, count in counts.items() if count > 1}


def _matches_for_incident(incident, matches: list[dict]) -> list[dict]:
    incident_sources = set(incident.source_ips)
    incident_assets = set(incident.affected_assets)
    return [
        match
        for match in matches
        if match["attack_type"] == incident.detection.attack_type
        and (
            incident_sources & set(match.get("source_ips", []))
            or incident_assets & set(match.get("affected_assets", []))
        )
    ]


def _incident_with_memory_context(
    incident,
    feedback_matches: list[dict],
    entity_matches: list[dict],
):
    if not feedback_matches and not entity_matches:
        return incident
    feedback_adjustment = sum(match.get("score_delta", 0) for match in feedback_matches)
    entity_adjustment = sum(match.get("score_delta", 0) for match in entity_matches)
    feedback_context = [
        {
            key: value
            for key, value in match.items()
            if key not in {"source_ips", "affected_assets"}
        }
        for match in feedback_matches
    ]
    return replace(
        incident,
        score_adjustment=max(-40, min(35, feedback_adjustment + entity_adjustment)),
        feedback_context=feedback_context,
        entity_context=entity_matches,
    )


def _feedback_score_delta(verdict: str) -> int:
    return {
        "false_positive": -30,
        "benign": -25,
        "expected": -20,
        "true_positive": 12,
        "needs_review": 0,
    }.get(verdict, 0)


def _entity_matches_for_incident(path: Path, incident) -> list[dict]:
    store = EntityStore(path)
    payload = incident.to_dict()
    candidates = []
    candidates.extend(("source_ip", value) for value in payload["source_ips"])
    candidates.extend(("asset", value) for value in payload["affected_assets"])
    candidates.extend(
        ("user", event.get("username", ""))
        for event in payload.get("evidence", [])
        if event.get("username") not in (None, "", "unknown")
    )
    matches = []
    seen = set()
    for entity_type, value in candidates:
        key = (entity_type, str(value).lower())
        if key in seen:
            continue
        seen.add(key)
        profile = store.get_entity(entity_type, str(value))
        if profile.incident_count == 0:
            continue
        delta = _entity_score_delta(profile.incident_count, profile.case_count)
        if not delta:
            continue
        matches.append(
            {
                "entity_type": entity_type,
                "value": profile.value,
                "incident_count": profile.incident_count,
                "case_count": profile.case_count,
                "last_seen": profile.last_seen,
                "score_delta": delta,
            }
        )
    return matches


def _entity_score_delta(incident_count: int, case_count: int) -> int:
    delta = 0
    if incident_count >= 1:
        delta += 5
    if incident_count >= 3:
        delta += 5
    if case_count >= 2:
        delta += 10
    return min(delta, 15)


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _matching_open_case_id(connection: sqlite3.Connection, payload: dict) -> int | None:
    new_assets = set(payload.get("affected_assets") or [])
    new_sources = set(payload.get("source_ips") or [])
    new_attack_types = set(payload.get("attack_types") or [payload.get("attack_type")])
    rows = connection.execute(
        """
        SELECT id, payload_json
        FROM cases
        WHERE state NOT IN ('resolved', 'closed')
        ORDER BY id DESC
        """
    ).fetchall()
    for case_id, raw_payload in rows:
        try:
            existing = json.loads(raw_payload)
        except json.JSONDecodeError:
            continue
        existing_assets = set(existing.get("affected_assets") or [])
        existing_sources = set(existing.get("source_ips") or [])
        existing_attack_types = set(
            existing.get("attack_types") or [existing.get("attack_type")]
        )
        if (
            new_attack_types & existing_attack_types
            and (new_assets & existing_assets or new_sources & existing_sources)
        ):
            return case_id
    return None


def _merge_case(connection: sqlite3.Connection, case_id: int, case: dict) -> None:
    row = connection.execute(
        """
        SELECT incident_ids, payload_json, history_json, score
        FROM cases
        WHERE id = ?
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        return
    raw_incident_ids, raw_payload, raw_history, current_score = row
    incident_ids = sorted(set(json.loads(raw_incident_ids)) | set(case["incident_ids"]))
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        payload = {}
    payload.setdefault("related_updates", []).append(case["payload"])
    payload["affected_assets"] = sorted(
        set(payload.get("affected_assets") or []) | set(case["payload"].get("affected_assets") or [])
    )
    payload["source_ips"] = sorted(
        set(payload.get("source_ips") or []) | set(case["payload"].get("source_ips") or [])
    )
    if payload.get("attack_types") or case["payload"].get("attack_types"):
        payload["attack_types"] = sorted(
            set(payload.get("attack_types") or [])
            | set(case["payload"].get("attack_types") or [case["payload"].get("attack_type")])
        )
    history = json.loads(raw_history or "[]")
    history.append({"event": f"merged related incident ids {', '.join(map(str, case['incident_ids']))}"})
    connection.execute(
        """
        UPDATE cases
        SET score = ?, incident_ids = ?, payload_json = ?, history_json = ?
        WHERE id = ?
        """,
        (
            max(current_score, case["score"]),
            json.dumps(incident_ids),
            json.dumps(payload),
            json.dumps(history),
            case_id,
        ),
    )
