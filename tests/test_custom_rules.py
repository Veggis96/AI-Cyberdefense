from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyberdefense_agent.custom_rules import load_local_rules
from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent


class CustomRuleTests(unittest.TestCase):
    def test_loads_simple_yaml_rule_and_detects_event(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "rules.yaml"
            path.write_text(
                """
rules:
    - name: Suspicious Curl Download
    attack_type: suspicious_download
    event_type: process_creation
    tactic: execution
    technique_id: T1059
    confidence: high
    base_score: 52
    summary: Suspicious command on {asset}
    conditions:
      - field: details.command_line
        contains: curl
""",
                encoding="utf-8",
            )

            rules = load_local_rules([path])
            report = DefenseAgent(extra_rules=rules).analyze(
                [
                    SecurityEvent(
                        timestamp="2026-07-02T12:00:00Z",
                        event_type="process_creation",
                        asset="workstation-01",
                        asset_criticality="high",
                        details={"command_line": "curl.exe http://example/file"},
                    )
                ]
            )

        self.assertEqual(report.incidents[0].detection.attack_type, "suspicious_download")
        self.assertEqual(report.incidents[0].detection.rule_name, "Suspicious Curl Download")
        self.assertEqual(report.incidents[0].severity, "high")

    def test_loads_json_rule_with_min_condition(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "rules.json"
            path.write_text(
                """
{
  "rules": [
    {
      "name": "Large Outbound Transfer",
      "attack_type": "large_transfer",
      "event_type": "data_transfer",
      "base_score": 61,
      "conditions": [
        {"field": "details.bytes_out", "min": 50000000}
      ]
    }
  ]
}
""",
                encoding="utf-8",
            )

            report = DefenseAgent(extra_rules=load_local_rules([path])).analyze(
                [
                    SecurityEvent(
                        timestamp="2026-07-02T12:00:00Z",
                        event_type="data_transfer",
                        asset="fileserver-01",
                        details={"bytes_out": 75_000_000},
                    )
                ]
            )

        self.assertEqual(report.incidents[0].detection.attack_type, "large_transfer")

    def test_loads_sigma_rule_with_modifiers_and_or_condition(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "sigma.yml"
            path.write_text(
                """
title: Suspicious PowerShell Or Certutil
description: Suspicious process execution
tags: [attack.execution, attack.t1059]
level: high
detection:
  selection_powershell:
    EventID: 4688
    CommandLine|contains|all: [powershell, encodedcommand]
  selection_certutil:
    EventID: 4688
    Image|endswith: certutil.exe
  condition: selection_powershell or selection_certutil
""",
                encoding="utf-8",
            )

            rules = load_local_rules([path])
            report = DefenseAgent(extra_rules=rules).analyze(
                [
                    SecurityEvent(
                        timestamp="2026-07-02T12:00:00Z",
                        event_type="process_creation",
                        asset="workstation-01",
                        details={
                            "command_line": "powershell.exe -EncodedCommand SQBFAFgAIAAo",
                            "process_name": "powershell.exe",
                        },
                    )
                ]
            )

        sigma_incident = next(
            incident
            for incident in report.incidents
            if incident.detection.rule_name == "Suspicious PowerShell Or Certutil"
        )
        self.assertEqual(sigma_incident.detection.technique_id, "T1059")


if __name__ == "__main__":
    unittest.main()
