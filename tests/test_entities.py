from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.entities import EntityStore
from cyberdefense_agent.events import SecurityEvent
from cyberdefense_agent.memory import IncidentMemory


class EntityProfileTests(unittest.TestCase):
    def test_profiles_source_asset_and_user_from_memory(self):
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

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            stats = IncidentMemory(db_path).store_report(report)
            store = EntityStore(db_path)
            source = store.get_entity("source_ip", "203.0.113.10")
            asset = store.get_entity("asset", "vpn-01")
            user = store.get_entity("user", "admin")

        self.assertEqual(source.incident_count, 1)
        self.assertEqual(source.case_count, 1)
        self.assertEqual(source.attack_types, {"brute_force": 1})
        self.assertEqual(asset.incident_ids, stats.last_stored_incident_ids)
        self.assertEqual(user.severities, {"high": 1})
        self.assertEqual(stats.top_entities["source_ip"][0]["value"], "203.0.113.10")

    def test_profiles_urls_from_web_evidence(self):
        report = DefenseAgent().analyze(
            [
                SecurityEvent(
                    timestamp="2026-07-02T12:10:00Z",
                    event_type="http_request",
                    source_ip="192.0.2.44",
                    destination_ip="10.0.0.5",
                    asset="web-01",
                    details={"path": "/products?id=1%27%20or%20%271%27=%271"},
                )
            ]
        )

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            IncidentMemory(db_path).store_report(report)
            urls = EntityStore(db_path).list_entities("url")

        self.assertEqual(urls[0].value, "/products?id=1%27%20or%20%271%27=%271")


if __name__ == "__main__":
    unittest.main()
