from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path


VALID_CASE_STATES = {
    "new",
    "investigating",
    "waiting",
    "resolved",
    "closed",
}


@dataclass(frozen=True)
class CaseEntry:
    id: int
    state: str
    title: str
    severity: str
    score: int
    incident_ids: list[int]
    owner: str
    priority: str
    notes: str
    history: list[dict]
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "incident_ids": self.incident_ids,
            "owner": self.owner,
            "priority": self.priority,
            "notes": self.notes,
            "history": self.history,
            "created_at": self.created_at,
        }


class CaseStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()

    def list_cases(self, limit: int = 50, state: str | None = None) -> list[CaseEntry]:
        if state is not None and state not in VALID_CASE_STATES:
            allowed = ", ".join(sorted(VALID_CASE_STATES))
            raise ValueError(f"Invalid state '{state}'. Expected one of: {allowed}")

        query = """
            SELECT id, state, title, severity, score, incident_ids, owner,
                   priority, notes, history_json, created_at
            FROM cases
        """
        params: tuple[object, ...]
        if state is None:
            query += " ORDER BY id DESC LIMIT ?"
            params = (limit,)
        else:
            query += " WHERE state = ? ORDER BY id DESC LIMIT ?"
            params = (state, limit)
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(query, params).fetchall()
        return [_case_from_row(row) for row in rows]

    def update_case(
        self,
        case_id: int,
        state: str | None = None,
        owner: str | None = None,
        priority: str | None = None,
        note: str | None = None,
    ) -> CaseEntry:
        if state is not None and state not in VALID_CASE_STATES:
            allowed = ", ".join(sorted(VALID_CASE_STATES))
            raise ValueError(f"Invalid state '{state}'. Expected one of: {allowed}")
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT state, owner, priority, notes, history_json FROM cases WHERE id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Case {case_id} does not exist")
            current_state, current_owner, current_priority, current_notes, raw_history = row
            next_state = state if state is not None else current_state
            next_owner = owner if owner is not None else current_owner
            next_priority = priority if priority is not None else current_priority
            next_notes = current_notes
            history = json.loads(raw_history or "[]")
            changes = []
            if state is not None and state != current_state:
                changes.append(f"state {current_state} -> {state}")
            if owner is not None and owner != current_owner:
                changes.append(f"owner {current_owner or 'unassigned'} -> {owner or 'unassigned'}")
            if priority is not None and priority != current_priority:
                changes.append(f"priority {current_priority} -> {priority}")
            if note:
                next_notes = f"{current_notes}\n{note}".strip()
                changes.append(f"note: {note}")
            if changes:
                history.append({"event": "; ".join(changes)})
            connection.execute(
                """
                UPDATE cases
                SET state = ?, owner = ?, priority = ?, notes = ?, history_json = ?
                WHERE id = ?
                """,
                (
                    next_state,
                    next_owner,
                    next_priority,
                    next_notes,
                    json.dumps(history),
                    case_id,
                ),
            )
        return self.get_case(case_id)

    def get_case(self, case_id: int) -> CaseEntry:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT id, state, title, severity, score, incident_ids, owner,
                       priority, notes, history_json, created_at
                FROM cases
                WHERE id = ?
                """,
                (case_id,),
            ).fetchone()
        if row is None:
            raise ValueError(f"Case {case_id} does not exist")
        return _case_from_row(row)

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
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


def _case_from_row(row) -> CaseEntry:
    (
        case_id,
        state,
        title,
        severity,
        score,
        raw_incident_ids,
        owner,
        priority,
        notes,
        raw_history,
        created_at,
    ) = row
    return CaseEntry(
        id=case_id,
        state=state,
        title=title,
        severity=severity,
        score=score,
        incident_ids=json.loads(raw_incident_ids),
        owner=owner,
        priority=priority,
        notes=notes,
        history=json.loads(raw_history or "[]"),
        created_at=created_at,
    )


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
