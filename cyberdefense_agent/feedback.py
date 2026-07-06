from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


VALID_VERDICTS = {
    "true_positive",
    "false_positive",
    "benign",
    "expected",
    "needs_review",
}


@dataclass(frozen=True)
class FeedbackEntry:
    id: int
    incident_id: int
    verdict: str
    note: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "verdict": self.verdict,
            "note": self.note,
            "created_at": self.created_at,
        }


class FeedbackStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()

    def add_feedback(self, incident_id: int, verdict: str, note: str = "") -> FeedbackEntry:
        if verdict not in VALID_VERDICTS:
            allowed = ", ".join(sorted(VALID_VERDICTS))
            raise ValueError(f"Invalid verdict '{verdict}'. Expected one of: {allowed}")

        with sqlite3.connect(self.path) as connection:
            incident_exists = connection.execute(
                "SELECT 1 FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if not incident_exists:
                raise ValueError(f"Incident {incident_id} does not exist")

            cursor = connection.execute(
                """
                INSERT INTO feedback (incident_id, verdict, note)
                VALUES (?, ?, ?)
                """,
                (incident_id, verdict, note),
            )
            feedback_id = cursor.lastrowid

        return self.get_feedback(feedback_id)

    def list_feedback(self, limit: int = 50) -> list[FeedbackEntry]:
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                """
                SELECT id, incident_id, verdict, note, created_at
                FROM feedback
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [FeedbackEntry(*row) for row in rows]

    def get_feedback(self, feedback_id: int) -> FeedbackEntry:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT id, incident_id, verdict, note, created_at
                FROM feedback
                WHERE id = ?
                """,
                (feedback_id,),
            ).fetchone()
        if row is None:
            raise ValueError(f"Feedback {feedback_id} does not exist")
        return FeedbackEntry(*row)

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
