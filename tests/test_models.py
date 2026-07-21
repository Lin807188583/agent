from datetime import date
import unittest

from mcp_ci.models import CheckReport, Finding, Severity, Suppression


class SeverityTests(unittest.TestCase):
    def test_severity_order_is_explicit(self) -> None:
        self.assertGreater(Severity.HIGH.rank, Severity.MEDIUM.rank)
        self.assertGreater(Severity.MEDIUM.rank, Severity.LOW.rank)

    def test_parse_is_case_insensitive(self) -> None:
        self.assertIs(Severity.parse("HiGh"), Severity.HIGH)


class ReportTests(unittest.TestCase):
    def test_report_fails_at_configured_threshold(self) -> None:
        report = CheckReport(
            target="demo",
            findings=[
                Finding(
                    rule_id="DEMO001",
                    title="Demo finding",
                    severity=Severity.MEDIUM,
                    message="A deterministic test finding.",
                    evidence={"field": "value"},
                    remediation="Fix the demo field.",
                )
            ],
        )

        self.assertTrue(report.should_fail(Severity.MEDIUM))
        self.assertFalse(report.should_fail(Severity.HIGH))

    def test_report_serialization_is_ci_friendly(self) -> None:
        report = CheckReport(target="demo")

        serialized = report.to_dict()

        self.assertEqual(serialized["target"], "demo")
        self.assertEqual(serialized["summary"]["total"], 0)
        self.assertEqual(serialized["findings"], [])

    def test_suppressed_findings_stay_visible_but_do_not_fail_ci(self) -> None:
        finding = Finding(
            rule_id="DEMO001",
            title="Demo finding",
            severity=Severity.HIGH,
            message="A deterministic test finding.",
            suppression=Suppression(
                rule_id="DEMO001",
                reason="Accepted for the migration window.",
                expires=date(2026, 8, 1),
            ),
        )
        report = CheckReport(target="demo", findings=[finding])

        serialized = report.to_dict()

        self.assertFalse(report.should_fail(Severity.LOW))
        self.assertEqual(serialized["summary"]["active"], 0)
        self.assertEqual(serialized["summary"]["suppressed"], 1)
        self.assertEqual(serialized["findings"][0]["status"], "suppressed")
        self.assertEqual(
            serialized["findings"][0]["suppression"]["reason"],
            "Accepted for the migration window.",
        )


if __name__ == "__main__":
    unittest.main()
