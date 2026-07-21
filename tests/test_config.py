from datetime import date
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mcp_ci.config import (
    ConfigError,
    apply_policy,
    apply_rule_controls,
    apply_suppressions,
    load_config,
)
from mcp_ci.models import CheckReport, Finding, Severity
from mcp_ci.probe import ProbeEvidence


def finding(tool: str = "legacy/read") -> Finding:
    return Finding(
        rule_id="SCHEMA005",
        title="Open schema",
        severity=Severity.LOW,
        message="The schema accepts undeclared parameters.",
        evidence={"tool": tool},
    )


class ConfigTests(unittest.TestCase):
    def write_config(self, directory: str, payload: object) -> Path:
        path = Path(directory) / "mcp-ci.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_tool_scoped_suppression_is_applied_and_audited(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "suppressions": [
                        {
                            "rule_id": "SCHEMA005",
                            "tool": "legacy/read",
                            "reason": "Tracked in issue #123.",
                            "expires": "2026-10-01",
                        }
                    ]
                },
            )
            config = load_config(path)
            report = CheckReport(
                target="demo", findings=[finding(), finding("other/read")]
            )

            apply_suppressions(report, config, today=date(2026, 7, 21))

        self.assertTrue(report.findings[0].is_suppressed)
        self.assertFalse(report.findings[1].is_suppressed)
        self.assertEqual(report.observations["suppressions"]["applied"], 1)

    def test_expired_suppression_does_not_apply(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "suppressions": [
                        {
                            "rule_id": "SCHEMA005",
                            "reason": "Old migration exception.",
                            "expires": "2026-07-20",
                        }
                    ]
                },
            )
            config = load_config(path)
            report = CheckReport(target="demo", findings=[finding()])

            apply_suppressions(report, config, today=date(2026, 7, 21))

        self.assertFalse(report.findings[0].is_suppressed)
        self.assertEqual(report.observations["suppressions"]["expired"], 1)

    def test_tool_scope_wins_and_expiration_date_is_inclusive(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "suppressions": [
                        {
                            "rule_id": "SCHEMA005",
                            "reason": "Rule-wide migration exception.",
                        },
                        {
                            "rule_id": "SCHEMA005",
                            "tool": "legacy/read",
                            "reason": "Narrower exception.",
                            "expires": "2026-07-21",
                        },
                    ]
                },
            )
            config = load_config(path)
            report = CheckReport(target="demo", findings=[finding()])

            apply_suppressions(report, config, today=date(2026, 7, 21))

        self.assertEqual(
            report.findings[0].suppression.reason,
            "Narrower exception.",
        )

    def test_unknown_rule_and_blank_reason_are_rejected(self) -> None:
        invalid_payloads = [
            {
                "suppressions": [
                    {"rule_id": "NOT_A_RULE", "reason": "No stable rule exists."}
                ]
            },
            {"suppressions": [{"rule_id": "SCHEMA005", "reason": "  "}]},
            {
                "suppressions": [
                    {
                        "rule_id": "SCHEMA005",
                        "reason": "Bad date shape.",
                        "expires": "20260721",
                    }
                ]
            },
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), TemporaryDirectory() as directory:
                path = self.write_config(directory, payload)
                with self.assertRaises(ConfigError):
                    load_config(path)

    def test_duplicate_scope_is_rejected_as_ambiguous(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "suppressions": [
                        {"rule_id": "SCHEMA005", "reason": "First."},
                        {"rule_id": "SCHEMA005", "reason": "Second."},
                    ]
                },
            )

            with self.assertRaisesRegex(ConfigError, "duplicate"):
                load_config(path)

    def test_http_rule_ids_are_valid_suppression_targets(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "suppressions": [
                        {
                            "rule_id": "HTTP001",
                            "reason": "Temporary Origin compatibility issue #456.",
                        }
                    ]
                },
            )

            config = load_config(path)

        self.assertEqual(config.suppressions[0].rule_id, "HTTP001")

    def test_strict_policy_and_rule_controls_are_parsed(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "rules": {
                        "disabled": ["SCHEMA005"],
                        "severity": {"TOOL004": "medium"},
                    },
                    "policy": {
                        "allowed_protocol_versions": ["2025-11-25"],
                        "required_capabilities": ["tools", "resources"],
                        "required_tools": ["health/read"],
                        "forbidden_tools": ["admin/*", "*/shell"],
                        "max_tools": 20,
                        "require_read_only": ["read_*"],
                    },
                    "suppressions": [],
                },
            )

            config = load_config(path)

        self.assertEqual(config.rules.disabled, ("SCHEMA005",))
        self.assertEqual(config.rules.severity, (("TOOL004", Severity.MEDIUM),))
        self.assertEqual(config.policy.required_capabilities, ("tools", "resources"))
        self.assertEqual(config.policy.forbidden_tools, ("admin/*", "*/shell"))
        self.assertEqual(config.policy.max_tools, 20)

    def test_invalid_policy_and_rule_controls_are_rejected(self) -> None:
        invalid_payloads = [
            {"rules": {"disabled": ["NOT_A_RULE"]}},
            {"rules": {"severity": {"TOOL004": "urgent"}}},
            {"rules": {"unknown": []}},
            {"policy": {"max_tools": True}},
            {"policy": {"max_tools": -1}},
            {"policy": {"forbidden_tools": ["admin/*", "admin/*"]}},
            {"policy": {"required_tools": [""]}},
            {"policy": {"unknown": []}},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), TemporaryDirectory() as directory:
                path = self.write_config(directory, payload)
                with self.assertRaises(ConfigError):
                    load_config(path)

    def test_policy_findings_enforce_repository_invariants(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "policy": {
                        "allowed_protocol_versions": ["2025-11-25"],
                        "required_capabilities": ["resources"],
                        "required_tools": ["health/read"],
                        "forbidden_tools": ["admin/*"],
                        "max_tools": 1,
                        "require_read_only": ["read_*"],
                    }
                },
            )
            config = load_config(path)

        tools = [
            {"name": "read_note", "annotations": {"readOnlyHint": False}},
            {"name": "admin/shell", "annotations": {"readOnlyHint": False}},
        ]
        evidence = ProbeEvidence(
            target="policy-fixture",
            requested_protocol_version="2025-11-25",
            initialize_response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                },
            },
            first_tools_response={"result": {"tools": tools}},
        )
        report = CheckReport(target="policy-fixture")

        apply_policy(report, evidence, config.policy)

        ids = {item.rule_id for item in report.findings}
        self.assertEqual(
            ids,
            {"POL001", "POL002", "POL003", "POL004", "POL005", "POL006"},
        )
        self.assertEqual(report.observations["policy"]["finding_count"], 6)

    def test_rule_controls_are_applied_and_audited(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                {
                    "rules": {
                        "disabled": ["SCHEMA005"],
                        "severity": {"TOOL004": "high"},
                    }
                },
            )
            config = load_config(path)
        report = CheckReport(
            target="fixture",
            findings=[
                Finding("SCHEMA005", "Open", Severity.LOW, "Open schema"),
                Finding("TOOL004", "Missing", Severity.LOW, "Missing description"),
            ],
        )

        apply_rule_controls(report, config.rules)

        self.assertEqual([item.rule_id for item in report.findings], ["TOOL004"])
        self.assertEqual(report.findings[0].severity, Severity.HIGH)
        self.assertEqual(report.observations["rule_controls"]["disabled_findings"], 1)
        self.assertEqual(report.observations["rule_controls"]["severity_overrides"], 1)


if __name__ == "__main__":
    unittest.main()
