from __future__ import annotations

from pathlib import Path

from .custom_rules import LocalRule, load_local_rules


PACK_DIR = Path(__file__).with_name("rule_packs")
AVAILABLE_PACKS = {"windows", "web", "identity", "network", "exfiltration"}


def load_rule_packs(pack_names: list[str] | None) -> list[LocalRule]:
    rules: list[LocalRule] = []
    for pack_name in pack_names or []:
        if pack_name not in AVAILABLE_PACKS:
            allowed = ", ".join(sorted(AVAILABLE_PACKS))
            raise ValueError(f"Unknown rule pack '{pack_name}'. Expected one of: {allowed}")
        rules.extend(load_local_rules([PACK_DIR / f"{pack_name}.yaml"]))
    return rules


def list_rule_packs() -> list[dict]:
    return [describe_rule_pack(name) for name in sorted(AVAILABLE_PACKS)]


def describe_rule_pack(pack_name: str) -> dict:
    if pack_name not in AVAILABLE_PACKS:
        allowed = ", ".join(sorted(AVAILABLE_PACKS))
        raise ValueError(f"Unknown rule pack '{pack_name}'. Expected one of: {allowed}")
    rules = load_local_rules([PACK_DIR / f"{pack_name}.yaml"])
    return {
        "name": pack_name,
        "path": str(PACK_DIR / f"{pack_name}.yaml"),
        "rule_count": len(rules),
        "rules": [
            {
                "name": rule.name,
                "attack_type": rule.attack_type,
                "event_type": rule.event_type,
                "tactic": rule.tactic,
                "technique_id": rule.technique_id,
                "confidence": rule.confidence,
                "base_score": rule.base_score,
            }
            for rule in rules
        ],
    }
