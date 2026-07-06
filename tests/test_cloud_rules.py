import unittest

from cyberdefense_agent.engine import DefenseAgent
from cyberdefense_agent.events import SecurityEvent


def cloud_event(provider, event_type="cloud_event", username="alice", **details):
    payload = {"provider": provider, **details}
    return SecurityEvent(
        timestamp="2026-07-02T12:00:00Z",
        event_type=event_type,
        source_ip=details.get("source_ip", "198.51.100.10"),
        username=username,
        asset=provider,
        asset_criticality="medium",
        details=payload,
    )


class CloudSaasRuleTests(unittest.TestCase):
    def test_detects_aws_root_login_and_access_key_creation(self):
        report = DefenseAgent().analyze(
            [
                cloud_event(
                    "aws_cloudtrail",
                    username="root",
                    event_name="ConsoleLogin",
                ),
                cloud_event(
                    "aws_cloudtrail",
                    username="alice",
                    event_name="CreateAccessKey",
                ),
            ]
        )

        attack_types = [incident.detection.attack_type for incident in report.incidents]

        self.assertIn("cloud_root_login", attack_types)
        self.assertIn("cloud_access_key_created", attack_types)
        root_incident = next(
            incident
            for incident in report.incidents
            if incident.detection.attack_type == "cloud_root_login"
        ).to_dict()

        self.assertEqual(
            root_incident["investigation"]["confidence_assessment"]["adjusted_confidence"],
            "high",
        )
        self.assertEqual(
            root_incident["investigation"]["response_readiness"]["overall_state"],
            "human_required",
        )

    def test_detects_cloud_failed_login_spike(self):
        report = DefenseAgent().analyze(
            [
                cloud_event("azure_ad", event_type="auth_failure", username="alice")
                for _ in range(3)
            ]
        )

        self.assertEqual(report.incidents[0].detection.attack_type, "cloud_failed_login_spike")

    def test_detects_okta_mfa_and_admin_assignment(self):
        report = DefenseAgent().analyze(
            [
                cloud_event(
                    "okta",
                    username="alice@example.com",
                    event_name="user.mfa.factor.activate",
                ),
                cloud_event(
                    "okta",
                    username="admin@example.com",
                    event_name="system.admin.grant",
                ),
            ]
        )

        attack_types = [incident.detection.attack_type for incident in report.incidents]

        self.assertIn("saas_mfa_method_added", attack_types)
        self.assertIn("saas_admin_role_assignment", attack_types)

    def test_detects_m365_oauth_consent(self):
        report = DefenseAgent().analyze(
            [
                cloud_event(
                    "m365",
                    username="alice@example.com",
                    event_name="Consent to application",
                    operation="Consent to application",
                )
            ]
        )

        self.assertEqual(report.incidents[0].detection.attack_type, "saas_oauth_consent")


if __name__ == "__main__":
    unittest.main()
