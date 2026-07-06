from __future__ import annotations

import re
from dataclasses import dataclass

from .playbooks import Playbook


@dataclass(frozen=True)
class ResponseStep:
    action: str
    mode: str = "dry-run"
    requires_approval: bool = True

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "mode": self.mode,
            "requires_approval": self.requires_approval,
        }


@dataclass(frozen=True)
class ResponsePlan:
    steps: list[ResponseStep]

    def to_dict(self) -> list[dict]:
        return [step.to_dict() for step in self.steps]


def build_response_plan(playbook: Playbook) -> ResponsePlan:
    return ResponsePlan(
        steps=[
            ResponseStep(action=action, requires_approval=_requires_approval(action))
            for action in playbook.actions
        ]
    )


def _requires_approval(action: str) -> bool:
    action_lower = action.lower()
    return any(
        re.search(pattern, action_lower)
        for pattern in (
            r"\bblock\b",
            r"\bisolate\b",
            r"\brestrict\b",
            r"\block\b",
            r"\brate-limit\b",
            r"\brotate\b",
            r"\bdisable\b",
            r"\bremove\b",
            r"\brevoke\b",
        )
    )
