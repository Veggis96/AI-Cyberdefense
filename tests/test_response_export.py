from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent
from cyberdefense_agent.response_export import write_response_bundle


class ResponseExportTests(unittest.TestCase):
    def test_writes_dry_run_response_bundle_json(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:08:00Z",
                event_type="data_transfer",
                source_ip="10.0.0.30",
                destination_ip="203.0.113.200",
                asset="fileserver-01",
                asset_criticality="critical",
                details={
                    "bytes_out": 250_000_000,
                    "destination_reputation": "unknown",
                },
            )
        ]
        report = DefenseAgent().analyze(events)

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "response.json"
            write_response_bundle(report, path)
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["mode"], "dry-run")
        self.assertEqual(payload["incident_count"], 1)
        self.assertIn("recommended_tickets", payload)
        self.assertGreaterEqual(len(payload["recommended_network_controls"]), 1)
        self.assertGreaterEqual(len(payload["countermeasure_proposals"]), 1)
        self.assertEqual(payload["countermeasure_proposals"][0]["execution_mode"], "dry-run")
        self.assertEqual(payload["countermeasure_proposals"][0]["readiness"], "human_required")
        self.assertEqual(
            payload["recommended_tickets"][0]["investigation"]["response_readiness"][
                "overall_state"
            ],
            "human_required",
        )

    def test_writes_dry_run_response_bundle_markdown(self):
        report = DefenseAgent().analyze(
            [
                SecurityEvent(
                    timestamp="2026-07-02T12:00:00Z",
                    event_type="malware_alert",
                    asset="workstation-01",
                    asset_criticality="high",
                    details={"indicator": "test-malware"},
                )
            ]
        )

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "response.md"
            write_response_bundle(report, path)
            markdown = path.read_text(encoding="utf-8")

        self.assertIn("AI Cyberdefense Response Bundle", markdown)
        self.assertIn("approval-required", markdown)
        self.assertIn("Readiness: `human_required`", markdown)
        self.assertIn("Countermeasure Proposals", markdown)
        self.assertIn("workstation-01", markdown)


if __name__ == "__main__":
    unittest.main()
