import unittest

from cyberdefense_agent.config import AgentConfig


class ConfigTests(unittest.TestCase):
    def test_loads_rule_controls_from_dict(self):
        config = AgentConfig.from_dict(
            {
                "rules": {
                    "disabled": ["port_scan", "WindowsSecurityRule"],
                    "score_overrides": {
                        "brute_force": 72,
                        "DataExfiltrationRule": 90,
                    },
                }
            }
        )

        self.assertEqual(config.disabled_rules, {"port_scan", "WindowsSecurityRule"})
        self.assertEqual(
            config.rule_score_overrides,
            {"brute_force": 72, "DataExfiltrationRule": 90},
        )


if __name__ == "__main__":
    unittest.main()
