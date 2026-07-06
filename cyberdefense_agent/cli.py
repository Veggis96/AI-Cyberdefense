from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

from .approvals import ApprovalStore, VALID_APPROVAL_STATES
from .baseline import load_baseline
from .cases import CaseStore, VALID_CASE_STATES
from .config import load_config
from .custom_rules import load_local_rules
from .dashboard import write_dashboard
from .engine import DefenseAgent
from .entities import EntityStore, VALID_ENTITY_TYPES
from .feedback import FeedbackStore, VALID_VERDICTS
from .memory import IncidentMemory
from .parsers import parse_events_with_diagnostics
from .response_export import write_response_bundle
from .rule_packs import AVAILABLE_PACKS, describe_rule_pack, list_rule_packs, load_rule_packs
from .threat_intel import load_threat_intel
from .triage import TriageStore, VALID_STATES


def build_feedback_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent feedback",
        description="Add or list analyst feedback for stored incidents.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    add_parser = subcommands.add_parser("add", help="Add feedback to an incident.")
    add_parser.add_argument("--memory-db", type=Path, required=True)
    add_parser.add_argument("--incident-id", type=int, required=True)
    add_parser.add_argument("--verdict", choices=sorted(VALID_VERDICTS), required=True)
    add_parser.add_argument("--note", default="")
    add_parser.add_argument("--json", action="store_true")

    list_parser = subcommands.add_parser("list", help="List recent feedback.")
    list_parser.add_argument("--memory-db", type=Path, required=True)
    list_parser.add_argument("--limit", type=int, default=50)
    list_parser.add_argument("--json", action="store_true")
    return parser


def build_triage_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent triage",
        description="List or update stored incident triage state.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="List stored incidents.")
    list_parser.add_argument("--memory-db", type=Path, required=True)
    list_parser.add_argument("--state", choices=sorted(VALID_STATES))
    list_parser.add_argument("--limit", type=int, default=50)
    list_parser.add_argument("--json", action="store_true")

    set_parser = subcommands.add_parser("set", help="Update incident triage state.")
    set_parser.add_argument("--memory-db", type=Path, required=True)
    set_parser.add_argument("--incident-id", type=int, required=True)
    set_parser.add_argument("--state", choices=sorted(VALID_STATES), required=True)
    set_parser.add_argument("--note")
    set_parser.add_argument("--json", action="store_true")
    return parser


def build_case_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent case",
        description="List or update investigation cases created from stored reports.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="List stored cases.")
    list_parser.add_argument("--memory-db", type=Path, required=True)
    list_parser.add_argument("--state", choices=sorted(VALID_CASE_STATES))
    list_parser.add_argument("--limit", type=int, default=50)
    list_parser.add_argument("--json", action="store_true")

    set_parser = subcommands.add_parser("set", help="Update case state.")
    set_parser.add_argument("--memory-db", type=Path, required=True)
    set_parser.add_argument("--case-id", type=int, required=True)
    set_parser.add_argument("--state", choices=sorted(VALID_CASE_STATES))
    set_parser.add_argument("--owner")
    set_parser.add_argument("--priority")
    set_parser.add_argument("--note")
    set_parser.add_argument("--json", action="store_true")
    return parser


def build_approval_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent approvals",
        description="List, approve, or reject pending countermeasure proposals.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="List approval requests.")
    list_parser.add_argument("--memory-db", type=Path, required=True)
    list_parser.add_argument("--state", choices=sorted(VALID_APPROVAL_STATES))
    list_parser.add_argument("--limit", type=int, default=50)
    list_parser.add_argument("--json", action="store_true")

    approve_parser = subcommands.add_parser("approve", help="Approve a proposal.")
    approve_parser.add_argument("--memory-db", type=Path, required=True)
    approve_parser.add_argument("--approval-id", type=int, required=True)
    approve_parser.add_argument("--by", default="")
    approve_parser.add_argument("--note", default="")
    approve_parser.add_argument("--json", action="store_true")

    reject_parser = subcommands.add_parser("reject", help="Reject a proposal.")
    reject_parser.add_argument("--memory-db", type=Path, required=True)
    reject_parser.add_argument("--approval-id", type=int, required=True)
    reject_parser.add_argument("--by", default="")
    reject_parser.add_argument("--note", default="")
    reject_parser.add_argument("--json", action="store_true")

    export_parser = subcommands.add_parser("export", help="Export approvals for handoff.")
    export_parser.add_argument("--memory-db", type=Path, required=True)
    export_parser.add_argument("--state", choices=sorted(VALID_APPROVAL_STATES), default="approved")
    export_parser.add_argument("--output", type=Path, required=True)
    export_parser.add_argument("--json", action="store_true")
    return parser


def build_entity_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent entity",
        description="List or inspect long-term entity profiles from incident memory.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="List entity profiles.")
    list_parser.add_argument("--memory-db", type=Path, required=True)
    list_parser.add_argument("--type", choices=sorted(VALID_ENTITY_TYPES), required=True)
    list_parser.add_argument("--limit", type=int, default=25)
    list_parser.add_argument("--json", action="store_true")

    show_parser = subcommands.add_parser("show", help="Show one entity profile.")
    show_parser.add_argument("--memory-db", type=Path, required=True)
    show_parser.add_argument("--type", choices=sorted(VALID_ENTITY_TYPES), required=True)
    show_parser.add_argument("--value", required=True)
    show_parser.add_argument("--json", action="store_true")
    return parser


def build_rule_pack_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent rule-pack",
        description="List or inspect bundled detection rule packs.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="List bundled rule packs.")
    list_parser.add_argument("--json", action="store_true")

    show_parser = subcommands.add_parser("show", help="Show rules in a bundled pack.")
    show_parser.add_argument("--name", choices=sorted(AVAILABLE_PACKS), required=True)
    show_parser.add_argument("--json", action="store_true")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent",
        description="Analyze security events and recommend defensive response actions.",
    )
    add_analysis_arguments(parser)
    return parser


def add_analysis_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--events",
        type=Path,
        required=True,
        help="Path to a JSONL event file.",
    )
    parser.add_argument(
        "--format",
        choices=[
            "auto",
            "jsonl",
            "csv",
            "nginx",
            "nginx_access",
            "cloud",
            "cloud_json",
            "aws_cloudtrail",
            "azure_ad",
            "okta",
            "m365",
        ],
        default="auto",
        help="Input event format. Auto-detects from extension by default.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a human report.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional JSON config for thresholds and allowlists.",
    )
    parser.add_argument(
        "--memory-db",
        type=Path,
        help="Optional SQLite database path for incident memory.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Optional JSON baseline for anomaly detection.",
    )
    parser.add_argument(
        "--html-report",
        type=Path,
        help="Optional path to write a static HTML dashboard report.",
    )
    parser.add_argument(
        "--threat-intel",
        type=Path,
        help="Optional local JSON threat intelligence indicators.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        action="append",
        default=[],
        help="Optional local JSON/YAML detection rule file. Can be supplied multiple times.",
    )
    parser.add_argument(
        "--rule-pack",
        choices=sorted(AVAILABLE_PACKS),
        action="append",
        default=[],
        help="Optional bundled detection pack. Can be supplied multiple times.",
    )
    parser.add_argument(
        "--response-bundle",
        type=Path,
        help="Optional JSON or Markdown dry-run response handoff path.",
    )


def build_watch_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberdefense-agent watch",
        description="Continuously analyze an event file and emit newly observed incidents.",
    )
    add_analysis_arguments(parser)
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between analysis passes.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        help="Stop after this many analysis passes. Useful for tests and demos.",
    )
    parser.add_argument(
        "--watch-state",
        type=Path,
        help="Optional JSON state file for remembered incident fingerprints.",
    )
    return parser


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "feedback":
        return feedback_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "triage":
        return triage_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "case":
        return case_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "approvals":
        return approvals_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "entity":
        return entity_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "rule-pack":
        return rule_pack_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "watch":
        return watch_main(sys.argv[2:])

    args = build_parser().parse_args()
    report = run_analysis(args)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())

    return 0


def run_analysis(args: argparse.Namespace):
    parse_result = parse_events_with_diagnostics(args.events, source_format=args.format)
    report = DefenseAgent(
        config=load_config(args.config),
        baseline=load_baseline(args.baseline),
        threat_intel=load_threat_intel(args.threat_intel),
        extra_rules=[*load_rule_packs(args.rule_pack), *load_local_rules(args.rules)],
    ).analyze(parse_result.events)
    report.import_diagnostics = parse_result.to_dict()
    if args.memory_db:
        try:
            report.memory = IncidentMemory(args.memory_db).store_report(report).to_dict()
        except (OSError, sqlite3.Error) as exc:
            report.memory = {"error": f"Memory storage unavailable: {exc}"}
    if args.html_report:
        write_dashboard(report, args.html_report)
    if args.response_bundle:
        write_response_bundle(report, args.response_bundle)
    return report


def watch_main(argv: list[str]) -> int:
    args = build_watch_parser().parse_args(argv)
    state_path = args.watch_state or args.events.with_suffix(args.events.suffix + ".watch_state.json")
    seen: set[str] = _load_watch_state(state_path)
    iteration = 0
    while True:
        iteration += 1
        report = run_analysis(args)
        new_incidents = [
            incident
            for incident in report.incidents
            if _incident_fingerprint(incident.to_dict()) not in seen
        ]
        for incident in new_incidents:
            seen.add(_incident_fingerprint(incident.to_dict()))
        _save_watch_state(state_path, seen)

        if args.json:
            payload = report.to_dict()
            payload["watch"] = {
                "iteration": iteration,
                "new_incident_count": len(new_incidents),
                "new_incidents": [incident.to_dict() for incident in new_incidents],
            }
            print(json.dumps(payload, indent=2))
        elif new_incidents:
            print(f"Watch iteration {iteration}: {len(new_incidents)} new incident(s).")
            for incident in new_incidents:
                print(
                    f" - {incident.severity.upper()} {incident.detection.attack_type}: "
                    f"{incident.detection.summary}"
                )
        else:
            print(f"Watch iteration {iteration}: no new incidents.")

        if args.max_iterations is not None and iteration >= args.max_iterations:
            return 0
        time.sleep(max(0.1, args.interval))


def _incident_fingerprint(incident: dict) -> str:
    return "|".join(
        [
            incident["attack_type"],
            incident.get("rule_name", ""),
            ",".join(incident["affected_assets"]),
            ",".join(incident["source_ips"]),
            incident["timeline"]["first_seen"],
            incident["timeline"]["last_seen"],
        ]
    )


def _load_watch_state(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8")).get("incident_fingerprints", []))
    except (OSError, json.JSONDecodeError):
        return set()


def _save_watch_state(path: Path, fingerprints: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"incident_fingerprints": sorted(fingerprints)}, indent=2),
        encoding="utf-8",
    )


def feedback_main(argv: list[str]) -> int:
    args = build_feedback_parser().parse_args(argv)
    store = FeedbackStore(args.memory_db)

    if args.command == "add":
        entry = store.add_feedback(args.incident_id, args.verdict, args.note)
        if args.json:
            print(json.dumps(entry.to_dict(), indent=2))
        else:
            print(
                f"Added feedback {entry.id} for incident {entry.incident_id}: "
                f"{entry.verdict}"
            )
        return 0

    if args.command == "list":
        entries = store.list_feedback(limit=args.limit)
        if args.json:
            print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        elif not entries:
            print("No feedback recorded.")
        else:
            for entry in entries:
                note = f" - {entry.note}" if entry.note else ""
                print(
                    f"{entry.id}: incident {entry.incident_id} "
                    f"{entry.verdict}{note} ({entry.created_at})"
                )
        return 0

    return 1


def triage_main(argv: list[str]) -> int:
    args = build_triage_parser().parse_args(argv)
    store = TriageStore(args.memory_db)

    if args.command == "list":
        entries = store.list_incidents(limit=args.limit, state=args.state)
        if args.json:
            print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        elif not entries:
            print("No incidents found.")
        else:
            for entry in entries:
                note = f" - {entry.analyst_note}" if entry.analyst_note else ""
                print(
                    f"{entry.id}: {entry.state} {entry.attack_type} "
                    f"{entry.severity} ({entry.score}/100){note}"
                )
        return 0

    if args.command == "set":
        entry = store.update_incident(
            incident_id=args.incident_id,
            state=args.state,
            analyst_note=args.note,
        )
        if args.json:
            print(json.dumps(entry.to_dict(), indent=2))
        else:
            print(f"Updated incident {entry.id}: {entry.state}")
        return 0

    return 1


def case_main(argv: list[str]) -> int:
    args = build_case_parser().parse_args(argv)
    store = CaseStore(args.memory_db)

    if args.command == "list":
        entries = store.list_cases(limit=args.limit, state=args.state)
        if args.json:
            print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        elif not entries:
            print("No cases found.")
        else:
            for entry in entries:
                incident_ids = ", ".join(map(str, entry.incident_ids))
                print(
                    f"{entry.id}: {entry.state} {entry.severity} "
                    f"({entry.score}/100) incidents={incident_ids} {entry.title}"
                )
        return 0

    if args.command == "set":
        entry = store.update_case(
            case_id=args.case_id,
            state=args.state,
            owner=args.owner,
            priority=args.priority,
            note=args.note,
        )
        if args.json:
            print(json.dumps(entry.to_dict(), indent=2))
        else:
            print(f"Updated case {entry.id}: {entry.state}")
        return 0

    return 1


def approvals_main(argv: list[str]) -> int:
    args = build_approval_parser().parse_args(argv)
    store = ApprovalStore(args.memory_db)

    if args.command == "list":
        entries = store.list_approvals(limit=args.limit, state=args.state)
        if args.json:
            print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        elif not entries:
            print("No approvals found.")
        else:
            for entry in entries:
                print(
                    f"{entry.id}: {entry.state} {entry.action_type} "
                    f"case={entry.case_id or '-'} incident={entry.incident_id or '-'} "
                    f"{entry.title}"
                )
                print(f"   {entry.command_preview}")
        return 0

    if args.command in {"approve", "reject"}:
        state = "approved" if args.command == "approve" else "rejected"
        entry = store.decide(
            approval_id=args.approval_id,
            state=state,
            decided_by=args.by,
            note=args.note,
        )
        if args.json:
            print(json.dumps(entry.to_dict(), indent=2))
        else:
            print(f"{state.capitalize()} approval {entry.id}.")
            print(f"Command preview remains dry-run: {entry.command_preview}")
        return 0

    if args.command == "export":
        entries = store.export_approvals(path=args.output, state=args.state)
        if args.json:
            print(
                json.dumps(
                    {
                        "exported_count": len(entries),
                        "state": args.state,
                        "output": str(args.output),
                    },
                    indent=2,
                )
            )
        else:
            print(f"Exported {len(entries)} approval(s) to {args.output}.")
        return 0

    return 1


def entity_main(argv: list[str]) -> int:
    args = build_entity_parser().parse_args(argv)
    store = EntityStore(args.memory_db)

    if args.command == "list":
        profiles = store.list_entities(entity_type=args.type, limit=args.limit)
        if args.json:
            print(json.dumps([profile.to_dict() for profile in profiles], indent=2))
        elif not profiles:
            print("No entity profiles found.")
        else:
            for profile in profiles:
                print(
                    f"{profile.value}: incidents={profile.incident_count} "
                    f"cases={profile.case_count} last_seen={profile.last_seen}"
                )
        return 0

    if args.command == "show":
        profile = store.get_entity(entity_type=args.type, value=args.value)
        if args.json:
            print(json.dumps(profile.to_dict(), indent=2))
        else:
            print(f"{profile.entity_type} {profile.value}")
            print(f"Incidents: {profile.incident_count}")
            print(f"Cases: {profile.case_count}")
            print(f"First seen: {profile.first_seen}")
            print(f"Last seen: {profile.last_seen}")
            print(f"Attack types: {profile.attack_types}")
            print(f"Severities: {profile.severities}")
        return 0

    return 1


def rule_pack_main(argv: list[str]) -> int:
    args = build_rule_pack_parser().parse_args(argv)

    if args.command == "list":
        packs = list_rule_packs()
        if args.json:
            print(json.dumps(packs, indent=2))
        else:
            for pack in packs:
                print(f"{pack['name']}: {pack['rule_count']} rule(s)")
        return 0

    if args.command == "show":
        pack = describe_rule_pack(args.name)
        if args.json:
            print(json.dumps(pack, indent=2))
        else:
            print(f"{pack['name']}: {pack['rule_count']} rule(s)")
            for rule in pack["rules"]:
                print(
                    f" - {rule['name']} ({rule['attack_type']}, "
                    f"{rule['technique_id']}, score {rule['base_score']})"
                )
        return 0

    return 1
