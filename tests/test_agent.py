import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cyberdefense_agent.baseline import AssetBaseline, BaselineProfile, UserBaseline
from cyberdefense_agent.config import AgentConfig
from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent
from cyberdefense_agent.feedback import FeedbackStore
from cyberdefense_agent.memory import IncidentMemory
from cyberdefense_agent.triage import TriageStore


class DefenseAgentTests(unittest.TestCase):
    def test_detects_brute_force(self):
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

        self.assertEqual(len(report.incidents), 1)
        self.assertEqual(report.incidents[0].detection.attack_type, "brute_force")
        self.assertEqual(report.incidents[0].severity, "high")

    def test_clean_events_have_no_incidents(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:00:00Z",
                event_type="auth_success",
                source_ip="10.0.0.10",
                username="alice",
                asset="vpn-01",
            )
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(report.incidents, [])

    def test_detects_encoded_web_attack_payload(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:10:00Z",
                event_type="http_request",
                source_ip="192.0.2.44",
                destination_ip="10.0.0.5",
                asset="web-01",
                asset_criticality="high",
                details={"path": "/products?id=1%27%20or%20%271%27=%271"},
            )
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(len(report.incidents), 1)
        self.assertEqual(report.incidents[0].detection.attack_type, "web_attack")

    def test_deduplicates_repeated_single_event_findings(self):
        events = [
            SecurityEvent(
                timestamp=f"2026-07-02T12:10:{index:02d}Z",
                event_type="http_request",
                source_ip="192.0.2.44",
                destination_ip="10.0.0.5",
                asset="web-01",
                asset_criticality="high",
                details={"path": f"/products?id={index}%27%20or%20%271%27=%271"},
            )
            for index in range(2)
        ]

        report = DefenseAgent().analyze(events)
        incident = report.incidents[0].to_dict()

        self.assertEqual(len(report.incidents), 1)
        self.assertEqual(incident["attack_type"], "web_attack")
        self.assertEqual(incident["occurrence_count"], 2)
        self.assertEqual(incident["explanation"]["deduplicated_occurrences"], 2)

    def test_detects_data_exfiltration_to_unknown_destination(self):
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

        self.assertEqual(len(report.incidents), 1)
        self.assertEqual(report.incidents[0].severity, "critical")

    def test_malformed_data_transfer_volume_does_not_crash_analysis(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:08:00Z",
                event_type="data_transfer",
                source_ip="10.0.0.30",
                destination_ip="203.0.113.200",
                asset="fileserver-01",
                asset_criticality="critical",
                details={
                    "bytes_out": "not-a-number",
                    "destination_reputation": "unknown",
                },
            )
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(report.incidents, [])

    def test_config_can_suppress_trusted_scanner(self):
        events = [
            SecurityEvent(
                timestamp=f"2026-07-02T12:03:{index:02d}Z",
                event_type="network_connection",
                source_ip="198.51.100.25",
                destination_ip="10.0.0.5",
                asset="web-01",
                details={"destination_port": port},
            )
            for index, port in enumerate([21, 22, 23, 25, 53, 80, 443, 8080])
        ]
        config = AgentConfig(trusted_scanner_ips={"198.51.100.25"})

        report = DefenseAgent(config=config).analyze(events)

        self.assertEqual(report.incidents, [])

    def test_config_can_disable_rule_by_attack_type(self):
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
        config = AgentConfig(disabled_rules={"brute_force"})

        report = DefenseAgent(config=config).analyze(events)

        self.assertEqual(report.incidents, [])

    def test_config_can_override_rule_score_by_rule_name(self):
        events = [
            SecurityEvent(
                timestamp=f"2026-07-02T12:00:{index:02d}Z",
                event_type="auth_failure",
                source_ip="203.0.113.10",
                username="admin",
                asset="vpn-01",
                asset_criticality="low",
            )
            for index in range(5)
        ]
        config = AgentConfig(rule_score_overrides={"BruteForceRule": 82})

        report = DefenseAgent(config=config).analyze(events)

        self.assertEqual(report.incidents[0].score, 82)
        self.assertEqual(report.incidents[0].severity, "critical")

    def test_port_scan_ignores_malformed_destination_ports(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:03:00Z",
                event_type="network_connection",
                source_ip="198.51.100.25",
                destination_ip="10.0.0.5",
                asset="web-01",
                details={"destination_port": "not-a-port"},
            ),
            *[
                SecurityEvent(
                    timestamp=f"2026-07-02T12:03:{index + 1:02d}Z",
                    event_type="network_connection",
                    source_ip="198.51.100.25",
                    destination_ip="10.0.0.5",
                    asset="web-01",
                    details={"destination_port": port},
                )
                for index, port in enumerate([21, 22, 23, 25, 53, 80, 443])
            ],
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(report.incidents, [])

    def test_incident_contains_agent_context(self):
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

        incident = DefenseAgent().analyze(events).incidents[0]
        incident_dict = incident.to_dict()

        self.assertEqual(incident_dict["technique_id"], "T1041")
        self.assertEqual(incident_dict["rule_name"], "DataExfiltrationRule")
        self.assertEqual(incident_dict["explanation"]["bytes_out"], 250_000_000)
        self.assertEqual(incident_dict["explanation"]["threshold"], 100_000_000)
        self.assertEqual(incident_dict["affected_assets"], ["fileserver-01"])
        self.assertEqual(incident_dict["timeline"]["first_seen"], "2026-07-02T12:08:00Z")
        self.assertTrue(incident_dict["response_plan"][1]["requires_approval"])
        self.assertIn("investigation", incident_dict)
        self.assertEqual(
            incident_dict["investigation"]["confidence_assessment"]["adjusted_confidence"],
            "high",
        )
        self.assertEqual(
            incident_dict["investigation"]["response_readiness"]["overall_state"],
            "human_required",
        )
        self.assertIn(
            "Destination ownership.",
            incident_dict["investigation"]["missing_context"],
        )

    def test_investigation_includes_related_event_context(self):
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
        events.append(
            SecurityEvent(
                timestamp="2026-07-02T12:01:00Z",
                event_type="auth_success",
                source_ip="203.0.113.10",
                username="admin",
                asset="vpn-01",
                asset_criticality="high",
            )
        )

        incident = DefenseAgent().analyze(events).incidents[0].to_dict()

        self.assertEqual(incident["attack_type"], "brute_force")
        self.assertEqual(
            incident["investigation"]["related_events"][0]["event_type"],
            "auth_success",
        )
        self.assertIn(
            "Was there a successful login from the same source after the failures?",
            incident["investigation"]["analyst_questions"],
        )

    def test_correlates_related_incidents_into_campaign(self):
        events = [
            *[
                SecurityEvent(
                    timestamp=f"2026-07-02T12:03:{index:02d}Z",
                    event_type="network_connection",
                    source_ip="198.51.100.25",
                    destination_ip="10.0.0.5",
                    asset="web-01",
                    asset_criticality="high",
                    details={"destination_port": port},
                )
                for index, port in enumerate([21, 22, 23, 25, 53, 80, 443, 8080])
            ],
            SecurityEvent(
                timestamp="2026-07-02T12:10:00Z",
                event_type="http_request",
                source_ip="198.51.100.25",
                destination_ip="10.0.0.5",
                asset="web-01",
                asset_criticality="high",
                details={"path": "/products?id=1%27%20or%20%271%27=%271"},
            ),
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(len(report.campaigns), 1)
        self.assertEqual(report.campaigns[0].campaign_id, "campaign-001")
        self.assertEqual(report.campaigns[0].confidence, "medium")
        self.assertEqual(
            report.campaigns[0].relation_reasons,
            ["shared_asset", "shared_source_ip"],
        )
        self.assertEqual(report.campaigns[0].attack_types, ["port_scan", "web_attack"])
        self.assertEqual(report.campaigns[0].affected_assets, ["web-01"])
        campaign_dict = report.campaigns[0].to_dict()
        self.assertEqual(
            [step["attack_type"] for step in campaign_dict["investigation_timeline"]],
            ["port_scan", "web_attack"],
        )
        self.assertIn("next_question", campaign_dict["analyst_assessment"])

    def test_correlation_window_prevents_distant_grouping(self):
        events = [
            *[
                SecurityEvent(
                    timestamp=f"2026-07-02T12:03:{index:02d}Z",
                    event_type="network_connection",
                    source_ip="198.51.100.25",
                    destination_ip="10.0.0.5",
                    asset="web-01",
                    asset_criticality="high",
                    details={"destination_port": port},
                )
                for index, port in enumerate([21, 22, 23, 25, 53, 80, 443, 8080])
            ],
            SecurityEvent(
                timestamp="2026-07-02T15:10:00Z",
                event_type="http_request",
                source_ip="198.51.100.25",
                destination_ip="10.0.0.5",
                asset="web-01",
                asset_criticality="high",
                details={"path": "/products?id=1%27%20or%20%271%27=%271"},
            ),
        ]

        report = DefenseAgent(
            config=AgentConfig(correlation_window_minutes=60)
        ).analyze(events)

        self.assertEqual(len(report.incidents), 2)
        self.assertEqual(report.campaigns, [])

    def test_incident_memory_tracks_repeats(self):
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
            memory = IncidentMemory(Path(directory) / "incidents.sqlite")
            memory.store_report(report)
            stats = memory.store_report(report)

        self.assertEqual(stats.stored_incidents, 2)
        self.assertEqual(stats.repeat_source_ips, {"10.0.0.30": 2})
        self.assertEqual(stats.repeat_assets, {"fileserver-01": 2})
        self.assertEqual(stats.triage_state_counts, {"new": 2})
        self.assertEqual(stats.open_cases, 1)
        self.assertEqual(len(stats.last_stored_case_ids), 1)

    def test_memory_merges_related_cases_and_suppresses_duplicate_approvals(self):
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
            memory = IncidentMemory(Path(directory) / "incidents.sqlite")
            first = memory.store_report(report)
            second = memory.store_report(DefenseAgent().analyze(events))

        self.assertEqual(first.last_stored_case_ids, second.last_stored_case_ids)
        self.assertEqual(second.open_cases, 1)
        self.assertEqual(len(second.last_stored_approval_ids), 0)

    def test_feedback_store_adds_and_lists_feedback(self):
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
            db_path = Path(directory) / "incidents.sqlite"
            stats = IncidentMemory(db_path).store_report(report)
            entry = FeedbackStore(db_path).add_feedback(
                incident_id=stats.last_stored_incident_ids[0],
                verdict="expected",
                note="Approved bulk export",
            )
            entries = FeedbackStore(db_path).list_feedback()

        self.assertEqual(entry.verdict, "expected")
        self.assertEqual(entries[0].note, "Approved bulk export")

    def test_memory_surfaces_feedback_context_for_later_reports(self):
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

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            first_report = DefenseAgent().analyze(events)
            first_stats = IncidentMemory(db_path).store_report(first_report)
            FeedbackStore(db_path).add_feedback(
                incident_id=first_stats.last_stored_incident_ids[0],
                verdict="false_positive",
                note="Known backup job",
            )

            second_report = DefenseAgent().analyze(events)
            second_stats = IncidentMemory(db_path).store_report(second_report)

        self.assertEqual(second_stats.feedback_matches[0]["verdict"], "false_positive")
        self.assertEqual(second_stats.feedback_matches[0]["note"], "Known backup job")

    def test_memory_feedback_adjusts_later_incident_score(self):
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

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            first_report = DefenseAgent().analyze(events)
            first_stats = IncidentMemory(db_path).store_report(first_report)
            FeedbackStore(db_path).add_feedback(
                incident_id=first_stats.last_stored_incident_ids[0],
                verdict="false_positive",
                note="Known backup job",
            )

            second_report = DefenseAgent().analyze(events)
            IncidentMemory(db_path).store_report(second_report)

        incident = second_report.incidents[0].to_dict()
        self.assertLess(incident["score_adjustment"], 0)
        self.assertLess(incident["score"], first_report.incidents[0].score)
        self.assertEqual(incident["feedback_context"][0]["verdict"], "false_positive")
        self.assertIn(
            "memory_score_decrease",
            [signal["signal"] for signal in incident["risk_signals"]],
        )

    def test_memory_entity_history_adjusts_later_incident_score(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:10:00Z",
                event_type="http_request",
                source_ip="192.0.2.44",
                asset="web-01",
                details={"path": "/products?id=1%27%20or%20%271%27=%271"},
            )
        ]

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            IncidentMemory(db_path).store_report(DefenseAgent().analyze(events))
            second_report = DefenseAgent().analyze(events)
            IncidentMemory(db_path).store_report(second_report)

        incident = second_report.incidents[0].to_dict()
        self.assertGreater(incident["score_adjustment"], 0)
        self.assertEqual(incident["entity_context"][0]["entity_type"], "source_ip")
        self.assertIn(
            "memory_score_increase",
            [signal["signal"] for signal in incident["risk_signals"]],
        )

    def test_triage_store_updates_and_filters_incident_state(self):
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

        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            stats = IncidentMemory(db_path).store_report(DefenseAgent().analyze(events))
            incident_id = stats.last_stored_incident_ids[0]
            store = TriageStore(db_path)

            updated = store.update_incident(
                incident_id=incident_id,
                state="investigating",
                analyst_note="Owner review started",
            )
            filtered = store.list_incidents(state="investigating")

        self.assertEqual(updated.state, "investigating")
        self.assertEqual(updated.analyst_note, "Owner review started")
        self.assertEqual([entry.id for entry in filtered], [incident_id])

    def test_baseline_detects_rare_port(self):
        baseline = BaselineProfile(
            assets={"web-01": AssetBaseline(common_ports={80, 443})}
        )
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:30:00Z",
                event_type="network_connection",
                source_ip="198.51.100.25",
                destination_ip="10.0.0.5",
                asset="web-01",
                details={"destination_port": 8443},
            )
        ]

        report = DefenseAgent(baseline=baseline).analyze(events)

        self.assertEqual(report.incidents[0].detection.attack_type, "rare_port_access")

    def test_baseline_detects_unusual_login_hour(self):
        baseline = BaselineProfile(
            users={"admin": UserBaseline(login_hours={8, 9, 10, 11, 12})}
        )
        events = [
            SecurityEvent(
                timestamp="2026-07-02T02:15:00Z",
                event_type="auth_success",
                source_ip="203.0.113.77",
                username="admin",
                asset="vpn-01",
                asset_criticality="high",
            )
        ]

        report = DefenseAgent(baseline=baseline).analyze(events)

        self.assertEqual(report.incidents[0].detection.attack_type, "unusual_login_time")

    def test_baseline_detects_data_transfer_spike(self):
        baseline = BaselineProfile(
            assets={"fileserver-01": AssetBaseline(max_bytes_out=75_000_000)}
        )
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:45:00Z",
                event_type="data_transfer",
                source_ip="10.0.0.30",
                destination_ip="203.0.113.200",
                asset="fileserver-01",
                asset_criticality="critical",
                details={
                    "bytes_out": 180_000_000,
                    "destination_reputation": "known",
                },
            )
        ]

        report = DefenseAgent(baseline=baseline).analyze(events)

        self.assertEqual(
            report.incidents[0].detection.attack_type,
            "data_transfer_anomaly",
        )

    def test_detects_high_signal_windows_security_events(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:00:00Z",
                event_type="audit_log_cleared",
                source_ip="unknown",
                username="admin",
                asset="dc-01",
                asset_criticality="critical",
            ),
            SecurityEvent(
                timestamp="2026-07-02T12:01:00Z",
                event_type="service_install",
                source_ip="unknown",
                username="admin",
                asset="dc-01",
                asset_criticality="critical",
                details={"service_name": "Updater"},
            ),
        ]

        report = DefenseAgent().analyze(events)
        attack_types = [incident.detection.attack_type for incident in report.incidents]

        self.assertEqual(
            attack_types,
            ["windows_audit_log_cleared", "windows_service_install"],
        )
        self.assertEqual(report.incidents[0].severity, "critical")

    def test_detects_suspicious_windows_process_command_line(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-02T12:02:00Z",
                event_type="process_creation",
                username="alice",
                asset="workstation-01",
                asset_criticality="high",
                details={
                    "command_line": (
                        "powershell.exe -NoP -EncodedCommand SQBFAFgAIAAo"
                    )
                },
            )
        ]

        report = DefenseAgent().analyze(events)

        self.assertEqual(
            report.incidents[0].detection.attack_type,
            "windows_suspicious_process",
        )


if __name__ == "__main__":
    unittest.main()
