from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .events import SecurityEvent
from .rules import Detection


@dataclass(frozen=True)
class LocalRule:
    name: str
    attack_type: str
    event_type: str
    summary: str
    tactic: str = "unknown"
    technique_id: str = "unknown"
    confidence: str = "medium"
    base_score: int = 45
    conditions: list[dict[str, Any]] = field(default_factory=list)
    condition_mode: str = "all"

    def detect(self, events: list[SecurityEvent]) -> list[Detection]:
        detections = []
        for event in events:
            if self.event_type != "*" and event.event_type != self.event_type:
                continue
            matched, explanations = _matches_conditions(event, self.conditions, self.condition_mode)
            if matched:
                detections.append(
                    Detection(
                        attack_type=self.attack_type,
                        summary=self._summary_for(event),
                        confidence=self.confidence,
                        base_score=self.base_score,
                        evidence=[event],
                        tactic=self.tactic,
                        technique_id=self.technique_id,
                        rule_name=self.name,
                        explanation={
                            "local_rule": self.name,
                            "event_type": event.event_type,
                            "conditions": explanations,
                        },
                    )
                )
        return detections

    def _summary_for(self, event: SecurityEvent) -> str:
        values = {
            "asset": event.asset,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "username": event.username,
            "event_type": event.event_type,
        }
        values.update({f"details.{key}": value for key, value in (event.details or {}).items()})
        try:
            return self.summary.format_map(_SafeFormat(values))
        except (KeyError, ValueError):
            return self.summary


def load_local_rules(paths: list[Path] | None) -> list[LocalRule]:
    rules: list[LocalRule] = []
    for path in paths or []:
        raw = _load_rule_file(path)
        if isinstance(raw, dict) and "rules" in raw:
            rule_items = raw["rules"]
        elif isinstance(raw, dict) and "detection" in raw:
            rule_items = [raw]
        else:
            rule_items = raw if isinstance(raw, list) else []
        for item in rule_items:
            rules.append(_rule_from_dict(item))
    return rules


def _rule_from_dict(raw: dict[str, Any]) -> LocalRule:
    if "detection" in raw and "conditions" not in raw:
        raw = _from_sigma_like(raw)
    name = str(raw.get("name") or raw.get("title") or "LocalRule")
    attack_type = str(raw.get("attack_type") or _slug(name))
    return LocalRule(
        name=name,
        attack_type=attack_type,
        event_type=str(raw.get("event_type", "*")),
        summary=str(raw.get("summary") or f"Local rule {name} matched."),
        tactic=str(raw.get("tactic", "unknown")),
        technique_id=str(raw.get("technique_id", "unknown")),
        confidence=str(raw.get("confidence", "medium")),
        base_score=int(raw.get("base_score", 45)),
        conditions=list(raw.get("conditions") or []),
        condition_mode=str(raw.get("condition_mode", "all")),
    )


def _from_sigma_like(raw: dict[str, Any]) -> dict[str, Any]:
    detection = dict(raw.get("detection") or {})
    selection_names = [
        name
        for name, value in detection.items()
        if name != "condition" and isinstance(value, dict)
    ]
    condition_expression = str(detection.get("condition") or "selection")
    selected_names, condition_mode = _sigma_condition_groups(condition_expression, selection_names)
    conditions = []
    event_type = str(raw.get("event_type", "*"))
    for name in selected_names:
        selection = dict(detection.get(name) or {})
        group_conditions = []
        for field, expected in selection.items():
            normalized = str(field).lower()
            if normalized in {"event_type", "eventid", "event_id"}:
                event_type = _event_type_from_sigma_event_id(expected)
                continue
            group_conditions.append(_sigma_condition(str(field), expected))
        if group_conditions:
            conditions.append({"all": group_conditions})
    tags = [str(tag) for tag in raw.get("tags", [])]
    technique_id = next((tag.upper() for tag in tags if tag.lower().startswith("attack.t")), "unknown")
    tactic = next((tag.split(".", 1)[1] for tag in tags if tag.lower().startswith("attack.") and not tag.lower().startswith("attack.t")), "unknown")
    return {
        "name": raw.get("title"),
        "attack_type": raw.get("attack_type"),
        "event_type": event_type,
        "summary": raw.get("description") or raw.get("title"),
        "tactic": tactic,
        "technique_id": technique_id.replace("ATTACK.", ""),
        "confidence": raw.get("level", "medium"),
        "base_score": raw.get("base_score", 45),
        "conditions": conditions,
        "condition_mode": condition_mode,
    }


def _matches_conditions(
    event: SecurityEvent,
    conditions: list[dict[str, Any]],
    mode: str = "all",
) -> tuple[bool, list[dict[str, Any]]]:
    explanations = []
    if not conditions:
        return True, explanations
    if mode == "any":
        for condition in conditions:
            matched, explanation = _matches_condition(event, condition)
            explanations.append(explanation)
            if matched:
                return True, explanations
        return False, explanations
    for condition in conditions:
        matched, explanation = _matches_condition(event, condition)
        if not matched:
            return False, explanations
        explanations.append(explanation)
    return True, explanations


def _matches_condition(event: SecurityEvent, condition: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    if "all" in condition:
        matched, explanations = _matches_conditions(event, list(condition["all"]), "all")
        return matched, {"all": explanations}
    if "any" in condition:
        matched, explanations = _matches_conditions(event, list(condition["any"]), "any")
        return matched, {"any": explanations}
    if "not" in condition:
        matched, explanation = _matches_condition(event, dict(condition["not"]))
        return not matched, {"not": explanation}
    field = str(condition.get("field", ""))
    value = _field_value(event, field)
    value_text = str(value).lower()
    explanation = {"field": field, "observed": value}
    if "equals" in condition:
        expected = condition["equals"]
        return value == expected or str(value) == str(expected), {**explanation, "equals": expected}
    if "contains" in condition:
        expected_values = _as_list(condition["contains"])
        matched = any(str(expected).lower() in value_text for expected in expected_values)
        return matched, {**explanation, "contains": condition["contains"]}
    if "contains_all" in condition:
        expected_values = _as_list(condition["contains_all"])
        matched = all(str(expected).lower() in value_text for expected in expected_values)
        return matched, {**explanation, "contains_all": condition["contains_all"]}
    if "endswith" in condition:
        expected_values = _as_list(condition["endswith"])
        matched = any(value_text.endswith(str(expected).lower()) for expected in expected_values)
        return matched, {**explanation, "endswith": condition["endswith"]}
    if "startswith" in condition:
        expected_values = _as_list(condition["startswith"])
        matched = any(value_text.startswith(str(expected).lower()) for expected in expected_values)
        return matched, {**explanation, "startswith": condition["startswith"]}
    if "regex" in condition:
        pattern = str(condition["regex"])
        return re.search(pattern, str(value), flags=re.IGNORECASE) is not None, {
            **explanation,
            "regex": pattern,
        }
    if "min" in condition:
        observed = _safe_float(value)
        expected = _safe_float(condition["min"])
        return observed is not None and expected is not None and observed >= expected, {
            **explanation,
            "min": condition["min"],
        }
    return False, {**explanation, "error": "unsupported condition"}


def _field_value(event: SecurityEvent, field: str) -> Any:
    if field.startswith("details."):
        return (event.details or {}).get(field.split(".", 1)[1], "")
    return getattr(event, field, "")


def _load_rule_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    root: dict[str, Any] = {}
    current_rule: dict[str, Any] | None = None
    current_list: str | None = None
    current_condition: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            root[stripped[:-1]] = []
            continue
        if stripped.startswith("- "):
            key_value = stripped[2:]
            if current_rule is None:
                current_rule = {}
                root.setdefault("rules", []).append(current_rule)
            if key_value.endswith(":"):
                current_list = key_value[:-1]
                current_rule[current_list] = []
                continue
            key, value = _split_yaml_pair(key_value)
            if current_list == "conditions" and indent >= 4:
                current_condition = {key: _yaml_value(value)}
                current_rule[current_list].append(current_condition)
            else:
                current_rule[key] = _yaml_value(value)
            continue
        key, value = _split_yaml_pair(stripped)
        if current_condition is not None and current_list == "conditions" and indent >= 6:
            current_condition[key] = _yaml_value(value)
        elif current_rule is not None and indent >= 2:
            if value == "":
                current_list = key
                current_rule[current_list] = []
                current_condition = None
            else:
                current_rule[key] = _yaml_value(value)
        else:
            root[key] = _yaml_value(value)
    return _parse_sigma_yaml(lines) or root


def _parse_sigma_yaml(lines: list[str]) -> dict[str, Any] | None:
    if any(line.startswith("rules:") for line in lines):
        return None
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- "):
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, value = _split_yaml_pair(stripped)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _yaml_value(value)
    if "detection" in root:
        return root
    return None


def _split_yaml_pair(text: str) -> tuple[str, str]:
    if ":" not in text:
        return text, ""
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _yaml_value(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
    try:
        return int(value)
    except ValueError:
        return value


def _sigma_field_name(field: str) -> str:
    mapping = {
        "commandline": "details.command_line",
        "command_line": "details.command_line",
        "image": "details.process_name",
        "newprocessname": "details.process_name",
        "sourceip": "source_ip",
        "src_ip": "source_ip",
        "destinationip": "destination_ip",
    }
    base = field.split("|", 1)[0]
    return mapping.get(base.lower().replace(" ", "").replace("_", ""), base)


def _sigma_condition(field: str, expected: Any) -> dict[str, Any]:
    parts = field.split("|")
    base_field = _sigma_field_name(parts[0])
    modifiers = [part.lower() for part in parts[1:]]
    if "contains" in modifiers and "all" in modifiers:
        return {"field": base_field, "contains_all": _as_list(expected)}
    if "contains" in modifiers:
        return {"field": base_field, "contains": expected}
    if "endswith" in modifiers:
        return {"field": base_field, "endswith": expected}
    if "startswith" in modifiers:
        return {"field": base_field, "startswith": expected}
    if isinstance(expected, str) and "*" in expected:
        return {"field": base_field, "contains": expected.strip("*")}
    return {"field": base_field, "equals": expected}


def _sigma_condition_groups(expression: str, selection_names: list[str]) -> tuple[list[str], str]:
    tokens = re.findall(r"[A-Za-z0-9_]+|\(|\)|and|or|not", expression, flags=re.IGNORECASE)
    names = [token for token in tokens if token in selection_names]
    if not names:
        names = ["selection"] if "selection" in selection_names else selection_names
    mode = "any" if re.search(r"\bor\b", expression, flags=re.IGNORECASE) else "all"
    excluded = {
        token
        for index, token in enumerate(tokens[1:], start=1)
        if tokens[index - 1].lower() == "not" and token in selection_names
    }
    return [name for name in names if name not in excluded], mode


def _event_type_from_sigma_event_id(value: Any) -> str:
    mapping = {
        "4625": "auth_failure",
        "4624": "auth_success",
        "4688": "process_creation",
        "4672": "privileged_logon",
        "4720": "user_created",
        "7045": "service_install",
        "1102": "audit_log_cleared",
    }
    return mapping.get(str(value), str(value))


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "local_rule"


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:
        return "unknown"
