from datetime import date
import json
import unittest
from xml.etree import ElementTree

from mcp_ci.models import CheckReport, Finding, Severity, Suppression
from mcp_ci.reporters import render_junit, render_sarif


def sample_report() -> CheckReport:
    return CheckReport(
        target="python server.py",
        requested_protocol_version="2025-11-25",
        negotiated_protocol_version="2025-11-25",
        findings=[
            Finding(
                rule_id="MCP002",
                title="Protocol noise",
                severity=Severity.HIGH,
                message="stdout contains non-protocol data.",
                evidence={"sample": ["debug"]},
                remediation="Write logs to stderr.",
            ),
            Finding(
                rule_id="SCHEMA005",
                title="Open schema",
                severity=Severity.LOW,
                message="The schema accepts undeclared parameters.",
                evidence={"tool": "legacy/read"},
                remediation="Reject unknown parameters.",
                suppression=Suppression(
                    rule_id="SCHEMA005",
                    tool="legacy/read",
                    reason="Legacy compatibility; issue #123.",
                    expires=date(2026, 10, 1),
                ),
            ),
        ],
    )


class JunitReporterTests(unittest.TestCase):
    def test_junit_has_failures_and_auditable_skips(self) -> None:
        root = ElementTree.fromstring(
            render_junit(sample_report(), threshold=Severity.MEDIUM, failed=True)
        )

        self.assertEqual(root.tag, "testsuite")
        self.assertEqual(root.attrib["tests"], "2")
        self.assertEqual(root.attrib["failures"], "1")
        self.assertEqual(root.attrib["skipped"], "1")
        self.assertIsNotNone(root.find("./testcase[@name='MCP002']/failure"))
        skipped = root.find("./testcase[@name='SCHEMA005']/skipped")
        self.assertIsNotNone(skipped)
        self.assertIn("issue #123", skipped.attrib["message"])
        properties = {
            item.attrib["name"]: item.attrib["value"]
            for item in root.findall("./properties/property")
        }
        self.assertEqual(properties["ci_status"], "fail")


class SarifReporterTests(unittest.TestCase):
    def test_sarif_has_stable_rules_levels_and_suppressions(self) -> None:
        payload = json.loads(
            render_sarif(sample_report(), threshold=Severity.MEDIUM, failed=True)
        )
        run = payload["runs"][0]
        results = {result["ruleId"]: result for result in run["results"]}

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(results["MCP002"]["level"], "error")
        self.assertEqual(results["SCHEMA005"]["level"], "note")
        self.assertEqual(
            results["SCHEMA005"]["suppressions"][0]["status"], "accepted"
        )
        self.assertIn(
            "issue #123", results["SCHEMA005"]["suppressions"][0]["justification"]
        )
        rule_ids = {
            rule["id"] for rule in run["tool"]["driver"]["rules"]
        }
        self.assertEqual(rule_ids, {"MCP002", "SCHEMA005"})


if __name__ == "__main__":
    unittest.main()
