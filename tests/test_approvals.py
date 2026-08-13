from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyberdefense_agent.approvals import ApprovalStore


class ApprovalExportTests(unittest.TestCase):
    def test_markdown_export_escapes_fenced_code_markers(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            db_path = Path(directory) / "incidents.sqlite"
            export_path = Path(directory) / "approvals.md"
            store = ApprovalStore(db_path)
            entry = store.add_approval(
                action_type="network_block",
                title="Fence Escape",
                description="Regression fixture",
                command_preview="first line\n```\n# injected heading",
            )
            store.decide(entry.id, "approved")

            store.export_approvals(export_path)
            markdown = export_path.read_text(encoding="utf-8")

        self.assertIn("` ` `", markdown)
        self.assertNotIn("\n```\n# injected heading", markdown)


if __name__ == "__main__":
    unittest.main()
