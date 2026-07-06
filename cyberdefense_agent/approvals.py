from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path


VALID_APPROVAL_STATES = {"pending", "approved", "rejected"}


@dataclass(frozen=True)
class ApprovalEntry:
    id: int
    state: str
    action_type: str
    title: str
    command_preview: str
    incident_id: int | None
    case_id: int | None
    decided_by: str
    decision_note: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "action_type": self.action_type,
            "title": self.title,
            "command_preview": self.command_preview,
            "incident_id": self.incident_id,
            "case_id": self.case_id,
            "decided_by": self.decided_by,
            "decision_note": self.decision_note,
            "created_at": self.created_at,
        }


class ApprovalStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()

    def add_approval(
        self,
        *,
        action_type: str,
        title: str,
        description: str,
        command_preview: str,
        incident_id: int | None = None,
        case_id: int | None = None,
    ) -> ApprovalEntry:
        with sqlite3.connect(self.path) as connection:
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
                    action_type,
                    title,
                    description,
                    command_preview,
                    incident_id,
                    case_id,
                    json.dumps(
                        {
                            "action_type": action_type,
                            "title": title,
                            "description": description,
                            "command_preview": command_preview,
                            "incident_id": incident_id,
                            "case_id": case_id,
                        }
                    ),
                ),
            )
            approval_id = cursor.lastrowid
        return self.get_approval(approval_id)

    def list_approvals(
        self,
        limit: int = 50,
        state: str | None = None,
    ) -> list[ApprovalEntry]:
        if state is not None and state not in VALID_APPROVAL_STATES:
            allowed = ", ".join(sorted(VALID_APPROVAL_STATES))
            raise ValueError(f"Invalid state '{state}'. Expected one of: {allowed}")
        query = """
            SELECT id, state, action_type, title, command_preview, incident_id,
                   case_id, decided_by, decision_note, created_at
            FROM approvals
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
        return [_approval_from_row(row) for row in rows]

    def decide(
        self,
        approval_id: int,
        state: str,
        decided_by: str = "",
        note: str = "",
    ) -> ApprovalEntry:
        if state not in {"approved", "rejected"}:
            raise ValueError("Approval decisions must be 'approved' or 'rejected'")
        with sqlite3.connect(self.path) as connection:
            exists = connection.execute(
                "SELECT 1 FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if not exists:
                raise ValueError(f"Approval {approval_id} does not exist")
            connection.execute(
                """
                UPDATE approvals
                SET state = ?, decided_by = ?, decision_note = ?, decided_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (state, decided_by, note, approval_id),
            )
        return self.get_approval(approval_id)

    def get_approval(self, approval_id: int) -> ApprovalEntry:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """
                SELECT id, state, action_type, title, command_preview, incident_id,
                       case_id, decided_by, decision_note, created_at
                FROM approvals
                WHERE id = ?
                """,
                (approval_id,),
            ).fetchone()
        if row is None:
            raise ValueError(f"Approval {approval_id} does not exist")
        return _approval_from_row(row)

    def export_approvals(self, path: Path, state: str = "approved") -> list[ApprovalEntry]:
        entries = self.list_approvals(limit=1000, state=state)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() == ".json":
            path.write_text(
                json.dumps([entry.to_dict() for entry in entries], indent=2),
                encoding="utf-8",
            )
        else:
            path.write_text(_render_markdown(entries, state), encoding="utf-8")
        return entries

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            ensure_approvals_schema(connection)


def ensure_approvals_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            action_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            command_preview TEXT NOT NULL,
            incident_id INTEGER,
            case_id INTEGER,
            state TEXT NOT NULL DEFAULT 'pending',
            decided_by TEXT NOT NULL DEFAULT '',
            decision_note TEXT NOT NULL DEFAULT '',
            decided_at TEXT,
            payload_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals (state)"
    )


def _approval_from_row(row) -> ApprovalEntry:
    return ApprovalEntry(*row)


def _render_markdown(entries: list[ApprovalEntry], state: str) -> str:
    lines = [
        "# Approved Countermeasure Handoff",
        "",
        f"State filter: `{state}`",
        "",
        "These are human-approved command previews. This export did not execute them.",
        "",
    ]
    if not entries:
        lines.append("No approvals matched the filter.")
    for entry in entries:
        lines.extend(
            [
                f"## Approval {entry.id}: {entry.title}",
                "",
                f"- State: {entry.state}",
                f"- Type: {entry.action_type}",
                f"- Case: {entry.case_id or '-'}",
                f"- Incident: {entry.incident_id or '-'}",
                f"- Decided by: {entry.decided_by or '-'}",
                f"- Note: {entry.decision_note or '-'}",
                "",
                "```text",
                entry.command_preview,
                "```",
                "",
            ]
        )
    return "\n".join(lines)
