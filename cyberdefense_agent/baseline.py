from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AssetBaseline:
    common_ports: set[int] = field(default_factory=set)
    max_bytes_out: int | None = None


@dataclass(frozen=True)
class UserBaseline:
    login_hours: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class BaselineProfile:
    assets: dict[str, AssetBaseline] = field(default_factory=dict)
    users: dict[str, UserBaseline] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BaselineProfile":
        assets = {
            asset: AssetBaseline(
                common_ports={int(port) for port in values.get("common_ports", [])},
                max_bytes_out=(
                    int(values["max_bytes_out"])
                    if values.get("max_bytes_out") is not None
                    else None
                ),
            )
            for asset, values in dict(raw.get("assets") or {}).items()
        }
        users = {
            user: UserBaseline(
                login_hours={int(hour) for hour in values.get("login_hours", [])}
            )
            for user, values in dict(raw.get("users") or {}).items()
        }
        return cls(assets=assets, users=users)


def load_baseline(path: Path | None) -> BaselineProfile | None:
    if path is None:
        return None
    with path.open("r", encoding="utf-8") as handle:
        return BaselineProfile.from_dict(json.load(handle))
