from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .events import SecurityEvent


@dataclass(frozen=True)
class ParseIssue:
    line_number: int
    message: str
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "message": self.message,
            "raw": self.raw,
        }


@dataclass(frozen=True)
class ParseResult:
    events: list[SecurityEvent]
    issues: list[ParseIssue] = field(default_factory=list)

    @property
    def skipped_count(self) -> int:
        return len(self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": len(self.events),
            "skipped_count": self.skipped_count,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class EventParser(Protocol):
    def parse(self, path: Path) -> list[SecurityEvent]:
        ...


class JsonLinesParser:
    def parse(self, path: Path) -> list[SecurityEvent]:
        result = self.parse_with_diagnostics(path)
        if result.issues:
            issue = result.issues[0]
            raise ValueError(f"Invalid JSON on line {issue.line_number}: {issue.message}")
        return result.events

    def parse_with_diagnostics(self, path: Path) -> ParseResult:
        events: list[SecurityEvent] = []
        issues: list[ParseIssue] = []
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    events.append(SecurityEvent.from_dict(json.loads(stripped)))
                except json.JSONDecodeError as exc:
                    issues.append(
                        ParseIssue(
                            line_number=line_number,
                            message=str(exc),
                            raw=stripped,
                        )
                    )
        return ParseResult(events=events, issues=issues)


class CsvParser:
    FIELD_ALIASES = {
        "timestamp": ("timestamp", "time", "date", "datetime", "event_time", "timecreated"),
        "event_type": ("event_type", "eventid", "event_id", "action", "type"),
        "source_ip": ("source_ip", "src_ip", "source", "client_ip", "ipaddress"),
        "destination_ip": ("destination_ip", "dst_ip", "destination", "server_ip"),
        "username": ("username", "user", "account", "account_name", "accountname"),
        "asset": ("asset", "host", "hostname", "computer", "computer_name"),
        "asset_criticality": ("asset_criticality", "criticality", "priority"),
    }

    WINDOWS_EVENT_TYPES = {
        "4625": "auth_failure",
        "4624": "auth_success",
        "4688": "process_creation",
        "4672": "privileged_logon",
        "4720": "user_created",
        "7045": "service_install",
        "1102": "audit_log_cleared",
    }

    DETAIL_ALIASES = {
        "command_line": (
            "command_line",
            "commandline",
            "process_command_line",
            "processcommandline",
        ),
        "process_name": (
            "process_name",
            "new_process_name",
            "newprocessname",
            "image",
        ),
        "parent_process_name": (
            "parent_process_name",
            "parentprocessname",
            "creator_process_name",
            "creatorprocessname",
        ),
        "service_name": ("service_name", "servicename"),
        "service_file_name": (
            "service_file_name",
            "servicefilename",
            "image_path",
            "imagepath",
            "service_path",
        ),
        "service_type": ("service_type", "servicetype"),
        "target_username": (
            "target_username",
            "targetusername",
            "target_user_name",
            "targetaccount",
        ),
        "subject_username": (
            "subject_username",
            "subjectusername",
            "subject_user_name",
            "caller_user_name",
        ),
    }

    def parse(self, path: Path) -> list[SecurityEvent]:
        return self.parse_with_diagnostics(path).events

    def parse_with_diagnostics(self, path: Path) -> ParseResult:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return ParseResult(events=[self._event_from_row(row) for row in rows])

    def _event_from_row(self, row: dict[str, Any]) -> SecurityEvent:
        normalized = {_normalize_key(key): value for key, value in row.items()}
        event_type = self._pick(normalized, "event_type", "unknown")
        event_type = self.WINDOWS_EVENT_TYPES.get(str(event_type), str(event_type))
        known_values = {
            field: self._pick(normalized, field, "unknown")
            for field in self.FIELD_ALIASES
            if field != "event_type"
        }
        details = {
            key: value
            for key, value in normalized.items()
            if key not in self._known_aliases() and value not in (None, "")
        }
        details.update(self._canonical_details(normalized))
        username = self._username_for_event(event_type, known_values, details)
        return SecurityEvent(
            timestamp=str(known_values["timestamp"]),
            event_type=event_type,
            source_ip=str(known_values["source_ip"]),
            destination_ip=str(known_values["destination_ip"]),
            username=username,
            asset=str(known_values["asset"]),
            asset_criticality=str(known_values["asset_criticality"]).lower(),
            details=details,
        )

    def _pick(self, row: dict[str, Any], field: str, default: str) -> Any:
        for alias in self.FIELD_ALIASES[field]:
            value = row.get(alias)
            if value not in (None, ""):
                return value
        return default

    def _known_aliases(self) -> set[str]:
        return {alias for aliases in self.FIELD_ALIASES.values() for alias in aliases}

    def _canonical_details(self, row: dict[str, Any]) -> dict[str, Any]:
        details = {}
        for field, aliases in self.DETAIL_ALIASES.items():
            for alias in aliases:
                value = row.get(alias)
                if value not in (None, ""):
                    details[field] = value
                    break
        return details

    def _username_for_event(
        self,
        event_type: str,
        known_values: dict[str, Any],
        details: dict[str, Any],
    ) -> str:
        if event_type == "user_created":
            return str(details.get("target_username") or known_values["username"])
        if event_type in {"privileged_logon", "service_install", "audit_log_cleared"}:
            return str(
                details.get("subject_username")
                or details.get("target_username")
                or known_values["username"]
            )
        return str(known_values["username"])


class NginxAccessLogParser:
    LOG_PATTERN = re.compile(
        r'(?P<source_ip>\S+) \S+ (?P<username>\S+) '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<body_bytes>\S+)'
        r'(?: "[^"]*" "(?P<user_agent>[^"]*)")?'
    )

    def parse(self, path: Path) -> list[SecurityEvent]:
        result = self.parse_with_diagnostics(path)
        if result.issues:
            issue = result.issues[0]
            raise ValueError(f"Invalid nginx access log on line {issue.line_number}")
        return result.events

    def parse_with_diagnostics(self, path: Path) -> ParseResult:
        events: list[SecurityEvent] = []
        issues: list[ParseIssue] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                match = self.LOG_PATTERN.match(stripped)
                if not match:
                    issues.append(
                        ParseIssue(
                            line_number=line_number,
                            message="Invalid nginx access log entry",
                            raw=stripped,
                        )
                    )
                    continue
                values = match.groupdict()
                events.append(
                    SecurityEvent(
                        timestamp=values["timestamp"],
                        event_type="http_request",
                        source_ip=values["source_ip"],
                        username=(
                            values["username"]
                            if values["username"] not in ("-", "")
                            else "unknown"
                        ),
                        asset=path.stem,
                        asset_criticality="medium",
                        details={
                            "method": values["method"],
                            "path": values["path"],
                            "protocol": values["protocol"],
                            "status": int(values["status"]),
                            "body_bytes": _safe_int(values["body_bytes"]),
                            "user_agent": values.get("user_agent") or "",
                        },
                    )
                )
        return ParseResult(events=events, issues=issues)


class CloudSaasJsonParser:
    def parse(self, path: Path) -> list[SecurityEvent]:
        return self.parse_with_diagnostics(path).events

    def parse_with_diagnostics(self, path: Path) -> ParseResult:
        events: list[SecurityEvent] = []
        issues: list[ParseIssue] = []
        with path.open("r", encoding="utf-8-sig") as handle:
            raw_text = handle.read().strip()
        if not raw_text:
            return ParseResult(events=[])
        try:
            if raw_text.startswith("[") or raw_text.startswith("{"):
                records = _records_from_json_document(json.loads(raw_text))
                for index, record in enumerate(records, start=1):
                    events.append(self._event_from_record(record, path))
            else:
                for line_number, line in enumerate(raw_text.splitlines(), start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        events.append(self._event_from_record(json.loads(stripped), path))
                    except json.JSONDecodeError as exc:
                        issues.append(ParseIssue(line_number, str(exc), stripped))
        except json.JSONDecodeError as exc:
            issues.append(ParseIssue(1, str(exc), raw_text[:240]))
        return ParseResult(events=events, issues=issues)

    def _event_from_record(self, record: dict[str, Any], path: Path) -> SecurityEvent:
        provider = _detect_cloud_provider(record)
        if provider == "aws_cloudtrail":
            return _aws_event(record)
        if provider == "azure_ad":
            return _azure_ad_event(record)
        if provider == "okta":
            return _okta_event(record)
        if provider == "m365":
            return _m365_event(record)
        return SecurityEvent.from_dict(
            {
                "timestamp": record.get("timestamp") or record.get("time") or "unknown",
                "event_type": record.get("event_type") or record.get("eventName") or "cloud_event",
                "source_ip": record.get("source_ip") or record.get("ipAddress") or "unknown",
                "username": record.get("username") or record.get("userPrincipalName") or "unknown",
                "asset": record.get("asset") or path.stem,
                "details": record,
            }
        )


def parse_events(path: Path, source_format: str = "auto") -> list[SecurityEvent]:
    parser = _select_parser(path, source_format)
    return parser.parse(path)


def parse_events_with_diagnostics(path: Path, source_format: str = "auto") -> ParseResult:
    parser = _select_parser(path, source_format)
    if hasattr(parser, "parse_with_diagnostics"):
        return parser.parse_with_diagnostics(path)
    return ParseResult(events=parser.parse(path))


def _select_parser(path: Path, source_format: str) -> EventParser:
    source_format = source_format.lower()
    if source_format == "auto":
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            return JsonLinesParser()
        if suffix == ".csv":
            return CsvParser()
        if suffix in (".log", ".access"):
            return NginxAccessLogParser()
        raise ValueError(f"Cannot auto-detect parser for {path}")
    if source_format == "jsonl":
        return JsonLinesParser()
    if source_format == "csv":
        return CsvParser()
    if source_format in ("nginx", "nginx_access"):
        return NginxAccessLogParser()
    if source_format in ("cloud", "cloud_json", "aws_cloudtrail", "azure_ad", "okta", "m365"):
        return CloudSaasJsonParser()
    raise ValueError(f"Unknown event format: {source_format}")


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_").replace("-", "_")


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def _records_from_json_document(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        for key in ("Records", "records", "value", "events"):
            if isinstance(raw.get(key), list):
                return [item for item in raw[key] if isinstance(item, dict)]
        return [raw]
    return []


def _detect_cloud_provider(record: dict[str, Any]) -> str:
    if "eventSource" in record or "awsRegion" in record:
        return "aws_cloudtrail"
    if "userPrincipalName" in record or "status" in record and "ipAddress" in record:
        return "azure_ad"
    if "actor" in record and "outcome" in record:
        return "okta"
    if "Workload" in record or "Operation" in record and "UserId" in record:
        return "m365"
    return "generic"


def _aws_event(record: dict[str, Any]) -> SecurityEvent:
    event_name = str(record.get("eventName", "cloud_event"))
    response = dict(record.get("responseElements") or {})
    error_code = record.get("errorCode")
    event_type = "cloud_event"
    if event_name == "ConsoleLogin":
        event_type = "auth_success" if response.get("ConsoleLogin") == "Success" and not error_code else "auth_failure"
    elif event_name in {"CreateUser", "CreateLoginProfile"}:
        event_type = "user_created"
    elif event_name in {"AttachUserPolicy", "PutUserPolicy", "CreateAccessKey"}:
        event_type = "privileged_logon"
    user_identity = dict(record.get("userIdentity") or {})
    username = (
        "root"
        if user_identity.get("type") == "Root"
        else user_identity.get("userName") or user_identity.get("principalId") or "unknown"
    )
    return SecurityEvent(
        timestamp=str(record.get("eventTime", "unknown")),
        event_type=event_type,
        source_ip=str(record.get("sourceIPAddress", "unknown")),
        username=str(username),
        asset=str(record.get("recipientAccountId") or record.get("eventSource") or "aws"),
        asset_criticality="medium",
        details={
            "provider": "aws_cloudtrail",
            "event_name": event_name,
            "event_source": record.get("eventSource", ""),
            "aws_region": record.get("awsRegion", ""),
            "error_code": error_code or "",
        },
    )


def _azure_ad_event(record: dict[str, Any]) -> SecurityEvent:
    status = dict(record.get("status") or {})
    error_code = str(status.get("errorCode", "0"))
    event_type = "auth_success" if error_code in {"0", "None", ""} else "auth_failure"
    return SecurityEvent(
        timestamp=str(record.get("createdDateTime") or record.get("timeGenerated") or "unknown"),
        event_type=event_type,
        source_ip=str(record.get("ipAddress", "unknown")),
        username=str(record.get("userPrincipalName") or record.get("userDisplayName") or "unknown"),
        asset=str(record.get("appDisplayName") or "azure_ad"),
        asset_criticality="medium",
        details={
            "provider": "azure_ad",
            "app": record.get("appDisplayName", ""),
            "client_app": record.get("clientAppUsed", ""),
            "status": status,
        },
    )


def _okta_event(record: dict[str, Any]) -> SecurityEvent:
    outcome = dict(record.get("outcome") or {})
    actor = dict(record.get("actor") or {})
    client = dict(record.get("client") or {})
    event_type = "auth_success" if outcome.get("result") == "SUCCESS" else "auth_failure"
    if str(record.get("eventType", "")).endswith("user.lifecycle.create"):
        event_type = "user_created"
    return SecurityEvent(
        timestamp=str(record.get("published", "unknown")),
        event_type=event_type,
        source_ip=str(client.get("ipAddress", "unknown")),
        username=str(actor.get("alternateId") or actor.get("displayName") or "unknown"),
        asset="okta",
        asset_criticality="medium",
        details={
            "provider": "okta",
            "event_type": record.get("eventType", ""),
            "event_name": record.get("eventType", ""),
            "outcome": outcome,
            "client": client,
        },
    )


def _m365_event(record: dict[str, Any]) -> SecurityEvent:
    operation = str(record.get("Operation") or record.get("operation") or "cloud_event")
    event_type = "auth_success" if operation in {"UserLoggedIn", "UserLoginSuccess"} else "cloud_event"
    if operation in {"Add user", "AddUser"}:
        event_type = "user_created"
    return SecurityEvent(
        timestamp=str(record.get("CreationTime") or record.get("TimeGenerated") or "unknown"),
        event_type=event_type,
        source_ip=str(record.get("ClientIP") or record.get("ClientIPAddress") or "unknown"),
        username=str(record.get("UserId") or record.get("UserKey") or "unknown"),
        asset=str(record.get("Workload") or "m365"),
        asset_criticality="medium",
        details={
            "provider": "m365",
            "operation": operation,
            "event_name": operation,
            "record_type": record.get("RecordType", ""),
        },
    )
