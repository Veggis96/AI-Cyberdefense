import unittest

from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent
from cyberdefense_agent.threat_intel import ThreatIndicator, ThreatIntel


class ThreatIntelTests(unittest.TestCase):
    def test_detects_ip_indicator_match(self):
        intel = ThreatIntel(
            indicators=[
                ThreatIndicator(
                    value="203.0.113.200",
                    indicator_type="ip",
                    threat="suspected exfiltration endpoint",
                    confidence="high",
                    source="unit-test",
                )
            ]
        )
        events = [
            SecurityEvent(
                timestamp="2026-07-02T13:00:00Z",
                event_type="network_connection",
                source_ip="10.0.0.30",
                destination_ip="203.0.113.200",
                asset="fileserver-01",
                asset_criticality="critical",
            )
        ]

        report = DefenseAgent(threat_intel=intel).analyze(events)

        self.assertEqual(report.incidents[0].detection.attack_type, "threat_intel_match")
        self.assertEqual(report.incidents[0].detection.confidence, "high")

    def test_detects_hash_indicator_match(self):
        intel = ThreatIntel(
            indicators=[
                ThreatIndicator(
                    value="44d88612fea8a8f36de82e1278abb02f",
                    indicator_type="hash",
                    threat="known malware test hash",
                    confidence="high",
                    source="unit-test",
                )
            ]
        )
        events = [
            SecurityEvent(
                timestamp="2026-07-02T13:05:00Z",
                event_type="edr_detection",
                source_ip="10.0.0.20",
                asset="workstation-22",
                asset_criticality="high",
                details={"file_hash": "44d88612fea8a8f36de82e1278abb02f"},
            )
        ]

        report = DefenseAgent(threat_intel=intel).analyze(events)
        attack_types = [incident.detection.attack_type for incident in report.incidents]

        self.assertIn("threat_intel_match", attack_types)


if __name__ == "__main__":
    unittest.main()
