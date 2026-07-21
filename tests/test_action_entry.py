import os
from unittest.mock import patch
import unittest

from scripts.action_entry import build_arguments, target_arguments


class ActionEntryTests(unittest.TestCase):
    def test_stdio_and_http_inputs_map_to_cli_arguments(self) -> None:
        cases = [
            (
                {"MCP_CI_STDIO": "python server.py", "MCP_CI_HTTP": ""},
                ["--stdio", "python server.py"],
            ),
            (
                {"MCP_CI_STDIO": "", "MCP_CI_HTTP": "https://example.com/mcp"},
                ["--http", "https://example.com/mcp"],
            ),
        ]
        for environment, expected in cases:
            with self.subTest(environment=environment), patch.dict(
                os.environ, environment, clear=True
            ):
                self.assertEqual(target_arguments(), expected)

    def test_exactly_one_action_target_is_required(self) -> None:
        cases = [
            {},
            {"MCP_CI_STDIO": "python server.py", "MCP_CI_HTTP": "https://x/mcp"},
        ]
        for environment in cases:
            with self.subTest(environment=environment), patch.dict(
                os.environ, environment, clear=True
            ):
                with self.assertRaisesRegex(SystemExit, "exactly one"):
                    target_arguments()

    def test_optional_policy_and_baseline_inputs_map_to_cli_arguments(self) -> None:
        environment = {
            "MCP_CI_STDIO": "python server.py",
            "MCP_CI_HTTP": "",
            "MCP_CI_FAIL_ON": "high",
            "MCP_CI_PROTOCOL_VERSION": "2025-11-25",
            "MCP_CI_TIMEOUT": "9",
            "MCP_CI_TOTAL_TIMEOUT": "45",
            "MCP_CI_FORMAT": "sarif",
            "MCP_CI_CONFIG": "mcp-ci.json",
            "MCP_CI_BASELINE": "mcp-ci-baseline.json",
            "MCP_CI_OUTPUT": "artifacts/results.sarif",
        }
        with patch.dict(os.environ, environment, clear=True):
            arguments = build_arguments()

        self.assertIn("--config", arguments)
        self.assertIn("mcp-ci.json", arguments)
        self.assertIn("--baseline", arguments)
        self.assertIn("mcp-ci-baseline.json", arguments)
        self.assertIn("--timeout", arguments)
        self.assertIn("9", arguments)
        self.assertIn("--total-timeout", arguments)
        self.assertIn("45", arguments)
        self.assertEqual(arguments[-2:], ["--output", "artifacts/results.sarif"])


if __name__ == "__main__":
    unittest.main()
