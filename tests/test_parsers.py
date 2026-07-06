from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.parsers import parse_events, parse_events_with_diagnostics


class ParserTests(unittest.TestCase):
    def test_nginx_access_log_normalizes_to_http_event(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "nginx_access.log"
            path.write_text(
                '192.0.2.44 - - [02/Jul/2026:12:10:00 +0000] '
                '"GET /products?id=1%27%20or%20%271%27=%271 HTTP/1.1" '
                '400 512 "-" "curl/8.0"\n',
                encoding="utf-8",
            )

            events = parse_events(path, source_format="nginx")
            report = DefenseAgent().analyze(events)

        self.assertEqual(events[0].event_type, "http_request")
        self.assertEqual(events[0].details["status"], 400)
        self.assertEqual(report.incidents[0].detection.attack_type, "web_attack")

    def test_nginx_diagnostics_skip_malformed_lines(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "nginx_access.log"
            path.write_text(
                "not an nginx line\n"
                '192.0.2.44 - - [02/Jul/2026:12:10:00 +0000] '
                '"GET /health HTTP/1.1" 200 42 "-" "curl/8.0"\n',
                encoding="utf-8",
            )

            result = parse_events_with_diagnostics(path, source_format="nginx")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.skipped_count, 1)
        self.assertEqual(result.issues[0].line_number, 1)

    def test_jsonl_diagnostics_skip_invalid_json(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                '{"timestamp":"2026-07-02T12:00:00Z","event_type":"auth_success"}\n'
                '{"timestamp":',
                encoding="utf-8",
            )

            result = parse_events_with_diagnostics(path, source_format="jsonl")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.skipped_count, 1)
        self.assertIn("Expecting value", result.issues[0].message)

    def test_jsonl_accepts_utf8_bom(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                '\ufeff{"timestamp":"2026-07-02T12:00:00Z","event_type":"auth_success"}\n',
                encoding="utf-8",
            )

            result = parse_events_with_diagnostics(path, source_format="jsonl")

        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.skipped_count, 0)

    def test_windows_security_csv_maps_event_id_to_auth_failure(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "windows_security.csv"
            path.write_text(
                "TimeCreated,EventID,IpAddress,AccountName,Computer,Criticality\n"
                "2026-07-02T12:00:00Z,4625,203.0.113.10,admin,vpn-01,high\n"
                "2026-07-02T12:00:04Z,4625,203.0.113.10,admin,vpn-01,high\n"
                "2026-07-02T12:00:08Z,4625,203.0.113.10,admin,vpn-01,high\n"
                "2026-07-02T12:00:12Z,4625,203.0.113.10,admin,vpn-01,high\n"
                "2026-07-02T12:00:16Z,4625,203.0.113.10,admin,vpn-01,high\n",
                encoding="utf-8",
            )

            events = parse_events(path, source_format="csv")
            report = DefenseAgent().analyze(events)

        self.assertEqual(events[0].event_type, "auth_failure")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(report.incidents[0].detection.attack_type, "brute_force")

    def test_windows_security_csv_maps_high_signal_event_ids(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "windows_security.csv"
            path.write_text(
                "TimeCreated,EventID,IpAddress,AccountName,Computer,Criticality\n"
                "2026-07-02T12:00:00Z,1102,,admin,dc-01,critical\n"
                "2026-07-02T12:01:00Z,7045,,admin,dc-01,critical\n",
                encoding="utf-8",
            )

            events = parse_events(path, source_format="csv")
            report = DefenseAgent().analyze(events)

        self.assertEqual(
            [event.event_type for event in events],
            ["audit_log_cleared", "service_install"],
        )
        self.assertEqual(
            [incident.detection.attack_type for incident in report.incidents],
            ["windows_audit_log_cleared", "windows_service_install"],
        )

    def test_windows_csv_canonicalizes_process_and_service_details(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "windows_security.csv"
            path.write_text(
                "TimeCreated,EventID,SubjectUserName,TargetUserName,Computer,"
                "NewProcessName,CommandLine,ParentProcessName,ServiceName,"
                "ServiceFileName,ServiceType,Criticality\n"
                "2026-07-02T12:00:00Z,4688,alice,,workstation-01,"
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,"
                "powershell.exe -NoP -EncodedCommand SQBFAFgAIAAo,"
                "C:\\Windows\\explorer.exe,,,,high\n"
                "2026-07-02T12:01:00Z,7045,admin,,server-01,,,,"
                "Updater,C:\\Temp\\updater.exe,kernel driver,critical\n"
                "2026-07-02T12:02:00Z,4720,admin,backdoor,dc-01,,,,,,critical\n",
                encoding="utf-8",
            )

            events = parse_events(path, source_format="csv")
            report = DefenseAgent().analyze(events)

        self.assertEqual(events[0].details["command_line"], "powershell.exe -NoP -EncodedCommand SQBFAFgAIAAo")
        self.assertEqual(events[0].details["process_name"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertEqual(events[1].details["service_name"], "Updater")
        self.assertEqual(events[2].username, "backdoor")
        self.assertEqual(
            [incident.detection.attack_type for incident in report.incidents],
            [
                "windows_suspicious_process",
                "windows_service_install",
                "windows_user_created",
            ],
        )
        self.assertEqual(
            report.incidents[1].detection.explanation["service_file_name"],
            "C:\\Temp\\updater.exe",
        )

    def test_cloudtrail_console_login_failure_normalizes_to_auth_failure(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = Path(directory) / "cloudtrail.json"
            path.write_text(
                """
{
  "Records": [
    {
      "eventTime": "2026-07-02T12:00:00Z",
      "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin",
      "sourceIPAddress": "203.0.113.10",
      "userIdentity": {"userName": "admin"},
      "responseElements": {"ConsoleLogin": "Failure"},
      "errorCode": "FailedAuthentication"
    }
  ]
}
""",
                encoding="utf-8",
            )

            events = parse_events(path, source_format="aws_cloudtrail")

        self.assertEqual(events[0].event_type, "auth_failure")
        self.assertEqual(events[0].source_ip, "203.0.113.10")
        self.assertEqual(events[0].details["provider"], "aws_cloudtrail")

    def test_azure_ad_okta_and_m365_cloud_json_normalization(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            azure_path = Path(directory) / "azure.json"
            azure_path.write_text(
                '[{"createdDateTime":"2026-07-02T12:00:00Z",'
                '"userPrincipalName":"alice@example.com","ipAddress":"198.51.100.5",'
                '"appDisplayName":"Office 365","status":{"errorCode":0}}]',
                encoding="utf-8",
            )
            okta_path = Path(directory) / "okta.json"
            okta_path.write_text(
                '[{"published":"2026-07-02T12:01:00Z","eventType":"user.session.start",'
                '"actor":{"alternateId":"bob@example.com"},"client":{"ipAddress":"198.51.100.6"},'
                '"outcome":{"result":"FAILURE"}}]',
                encoding="utf-8",
            )
            m365_path = Path(directory) / "m365.json"
            m365_path.write_text(
                '[{"CreationTime":"2026-07-02T12:02:00Z","Operation":"UserLoggedIn",'
                '"UserId":"carol@example.com","ClientIP":"198.51.100.7","Workload":"Exchange"}]',
                encoding="utf-8",
            )

            azure = parse_events(azure_path, source_format="azure_ad")
            okta = parse_events(okta_path, source_format="okta")
            m365 = parse_events(m365_path, source_format="m365")

        self.assertEqual(azure[0].event_type, "auth_success")
        self.assertEqual(okta[0].event_type, "auth_failure")
        self.assertEqual(m365[0].event_type, "auth_success")
        self.assertEqual(m365[0].asset, "Exchange")


if __name__ == "__main__":
    unittest.main()
