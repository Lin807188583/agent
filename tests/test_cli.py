import asyncio
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from mcp_ci.cli import main
from tests.fixtures.http_fixture import RunningHttpFixture


FIXTURE = Path(__file__).parent / "fixtures" / "mcp_fixture.py"
COMMAND = f'{sys.executable} "{FIXTURE}"'


class CliTests(unittest.TestCase):
    def test_good_fixture_prints_text_and_exits_zero(self) -> None:
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = main(["check", "--stdio", COMMAND])

        self.assertEqual(exit_code, 0)
        self.assertIn("PASS", stdout.getvalue())
        self.assertIn("tools executed: no", stdout.getvalue())

    def test_json_output_has_stable_report_shape(self) -> None:
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = main(
                ["check", "--stdio", COMMAND, "--format", "json", "--fail-on", "high"]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["target"], COMMAND)
        self.assertFalse(payload["observations"]["tools_were_executed"])
        self.assertFalse(payload["observations"]["resources_were_read"])
        self.assertFalse(payload["observations"]["prompts_were_resolved"])

    def test_missing_executable_is_an_operational_error(self) -> None:
        stderr = StringIO()

        with redirect_stderr(stderr):
            exit_code = main(["check", "--stdio", "definitely-not-a-real-command"])

        self.assertEqual(exit_code, 2)
        self.assertIn("cannot start target command", stderr.getvalue())

    def test_timeout_values_must_be_positive_and_finite(self) -> None:
        cases = [
            ("--timeout", "0"),
            ("--timeout", "nan"),
            ("--timeout", "inf"),
            ("--total-timeout", "0"),
            ("--total-timeout", "nan"),
            ("--total-timeout", "inf"),
        ]
        for option, value in cases:
            stderr = StringIO()
            with self.subTest(option=option, value=value), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "check",
                        "--stdio",
                        "definitely-not-a-real-command",
                        option,
                        value,
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertIn(option, stderr.getvalue())
            self.assertNotIn("cannot start target command", stderr.getvalue())

    def test_total_timeout_stops_a_slow_probe(self) -> None:
        async def slow_probe(*args: object, **kwargs: object) -> object:
            await asyncio.sleep(1)
            raise AssertionError("the total timeout should cancel the probe")

        stderr = StringIO()
        with patch("mcp_ci.cli.run_stdio_probe", new=slow_probe), redirect_stderr(
            stderr
        ):
            exit_code = main(
                [
                    "check",
                    "--stdio",
                    COMMAND,
                    "--total-timeout",
                    "0.01",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("total timeout", stderr.getvalue())

    def test_sarif_output_can_be_written_to_a_file(self) -> None:
        stdout = StringIO()
        with TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "mcp-ci.sarif"

            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "check",
                        "--stdio",
                        COMMAND,
                        "--format",
                        "sarif",
                        "--output",
                        str(output),
                    ]
                )

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(payload["version"], "2.1.0")

    def test_invalid_config_fails_before_starting_target(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as directory:
            config = Path(directory) / "mcp-ci.json"
            config.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {"rule_id": "SCHEMA005", "reason": ""}
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "check",
                        "--stdio",
                        "definitely-not-a-real-command",
                        "--config",
                        str(config),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("reason", stderr.getvalue())
        self.assertNotIn("cannot start target command", stderr.getvalue())

    def test_configured_policy_is_enforced_by_cli(self) -> None:
        stdout = StringIO()
        with TemporaryDirectory() as directory:
            config = Path(directory) / "mcp-ci.json"
            config.write_text(
                json.dumps(
                    {
                        "policy": {
                            "required_capabilities": ["tools"],
                            "max_tools": 0,
                        }
                    }
                ),
                encoding="utf-8",
            )
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "check",
                        "--stdio",
                        COMMAND,
                        "--config",
                        str(config),
                        "--format",
                        "json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertIn("POL005", {item["rule_id"] for item in payload["findings"]})
        self.assertTrue(payload["observations"]["policy"]["configured"])

    def test_http_target_runs_the_same_report_pipeline(self) -> None:
        stdout = StringIO()
        with RunningHttpFixture() as fixture, redirect_stdout(stdout):
            exit_code = main(
                ["check", "--http", fixture.url, "--format", "json"]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["observations"]["transport"], "http")
        self.assertEqual(
            payload["observations"]["transport_checks"]["origin_status"], 403
        )
        self.assertNotIn("fixture-session-4f793f4a", stdout.getvalue())

    def test_check_requires_exactly_one_transport_target(self) -> None:
        invalid_argv = [
            ["check"],
            ["check", "--stdio", COMMAND, "--http", "https://example.com/mcp"],
        ]
        for argv in invalid_argv:
            with self.subTest(argv=argv), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_baseline_can_be_written_and_checked(self) -> None:
        with TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            written_stdout = StringIO()
            with redirect_stdout(written_stdout):
                written_exit = main(
                    [
                        "check",
                        "--stdio",
                        COMMAND,
                        "--write-baseline",
                        str(baseline),
                        "--format",
                        "json",
                    ]
                )
            checked_stdout = StringIO()
            with redirect_stdout(checked_stdout):
                checked_exit = main(
                    [
                        "check",
                        "--stdio",
                        COMMAND,
                        "--baseline",
                        str(baseline),
                        "--format",
                        "json",
                    ]
                )

        written = json.loads(written_stdout.getvalue())
        checked = json.loads(checked_stdout.getvalue())
        self.assertEqual(written_exit, 0)
        self.assertEqual(checked_exit, 0)
        self.assertEqual(written["observations"]["baseline"]["mode"], "write")
        self.assertEqual(checked["observations"]["baseline"]["finding_count"], 0)

    def test_baseline_read_and_write_are_mutually_exclusive(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "check",
                        "--stdio",
                        COMMAND,
                        "--baseline",
                        "old.json",
                        "--write-baseline",
                        "new.json",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_invalid_baseline_fails_before_starting_target(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            baseline.write_text("{}", encoding="utf-8")
            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "check",
                        "--stdio",
                        "definitely-not-a-real-command",
                        "--baseline",
                        str(baseline),
                    ]
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("baseline", stderr.getvalue())
        self.assertNotIn("cannot start target command", stderr.getvalue())

    def test_remote_cleartext_http_is_an_operational_error(self) -> None:
        stderr = StringIO()

        with redirect_stderr(stderr):
            exit_code = main(
                ["check", "--http", "http://mcp.example.com/mcp"]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("loopback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
