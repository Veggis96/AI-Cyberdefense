from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyberdefense_agent.dashboard import write_dashboard
from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent


class DashboardTests(unittest.TestCase):
    def test_writes_html_dashboard(self):
        events = [
            SecurityEvent(
                timestamp=f"2026-07-02T12:00:{index:02d}Z",
                event_type="auth_failure",
                source_ip="203.0.113.10",
                username="admin",
                asset="vpn-01",
                asset_criticality="high",
            )
            for index in range(5)
        ]
        report = DefenseAgent().analyze(events)
        report.import_diagnostics = {
            "event_count": 5,
            "skipped_count": 1,
            "issues": [
                {
                    "line_number": 99,
                    "message": "Invalid JSON",
                    "raw": '{"timestamp":',
                }
            ],
        }

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "report.html"
            write_dashboard(report, path)
            html = path.read_text(encoding="utf-8")

        self.assertIn("AI Cyberdefense Report", html)
        self.assertIn("brute_force", html)
        self.assertIn("BruteForceRule", html)
        self.assertIn("failed_login_count", html)
        self.assertIn("Import Diagnostics", html)
        self.assertIn("Invalid JSON", html)
        self.assertIn("Response Plan", html)
        self.assertIn("Search incidents", html)
        self.assertIn("data-toggle-details", html)
        self.assertIn("data-severity", html)
        self.assertIn("Risk signals", html)
        self.assertIn("Open Cases", html)


if __name__ == "__main__":
    unittest.main()
