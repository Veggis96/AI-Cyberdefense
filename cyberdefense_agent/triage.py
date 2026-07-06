from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


VALID_STATES = {
    "new",
    "investigating",
    "benign",
    "confirmed",
    "resolved",
}


@dataclass(frozen=True)
class TriageEntry:
    id: int
    state: str
    analyst_note: str
    attack_type: str
    severity: str
    score: int
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "analyst_note": self.analyst_note,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "score": self.score,
            "created_at": self.created_at,
        }


class TriageStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()

    def update_incident(
        self,
        incident_id: int,
        state: str,
        analyst_note: str | None = None,
    ) -> TriageEntry:
        if state not in VALID_STATES:
            allowed = ", ".join(sorted(VALID_STATES))
            raise ValueError(f"Invalid state '{state}'. Expected one of: {allowed}")

        with sqlite3.connect(self.path) as connection:
            incident_exists = connection.execute(
                "SELECT 1 FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if not incident_exists:
                raise ValueError(f"Incident {incident_id} does not exist")

            if analyst_note is None:
                connection.execute(
                    "UPDATE incidents SET state = ? WHERE id = ?",
                    (state, incident_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE incidents
                    SET state = ?, analyst_note = ?
                    WHERE id = ?
                    """,
                    (state, analyst_note, incident_id),
                )
        return self.get_incident(incident_id)

    def list_incidents(self, limit: int = 50, state: str | None = None) -> list[TriageEntry]:
        if state is not None and state not in VALID_STATES:
            allowed = ", ".join(sorted(VALID_STATES))
            raise ValueError(f"Invalid state '{state}'. Expected one of: {allowed}")

        query = """
            SELECT id, state, analyst_note, attack_type, severity, score, created_at
            FROM incidents
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
        return [TriageEntry(*row) for row in rows]

    def get_incident(self, incident_id: int) -> TriageEntry:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT id, state, analyst_note, attack_type, severity, score, created_at
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()
        if row is None:
            raise ValueError(f"Incident {incident_id} does not exist")
        return TriageEntry(*row)

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
                "CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents (state)"
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
