import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest

from examples.good_http_server import GoodMcpHandler, McpHttpServer


ROOT = Path(__file__).resolve().parents[1]
GOOD_SERVER = ROOT / "examples" / "good_server.py"
BAD_SERVER = ROOT / "examples" / "bad_server.py"


def run_check(
    server: Path,
    report_format: str = "text",
    *extra_arguments: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    target = f'{sys.executable} "{server}"'
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_ci",
            "check",
            "--stdio",
            target,
            "--format",
            report_format,
            *extra_arguments,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def run_http_check(url: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_ci",
            "check",
            "--http",
            url,
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


class EndToEndTests(unittest.TestCase):
    def test_good_server_passes_default_ci_threshold(self) -> None:
        completed = run_check(GOOD_SERVER)

        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("result: PASS", completed.stdout)
        self.assertIn("findings: none", completed.stdout)

    def test_bad_server_fails_and_teaches_multiple_rule_families(self) -> None:
        completed = run_check(BAD_SERVER, "json")

        payload = json.loads(completed.stdout)
        finding_ids = {finding["rule_id"] for finding in payload["findings"]}
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        self.assertEqual(payload["ci"]["status"], "fail")
        self.assertTrue(
            {
                "MCP002",
                "MCP004",
                "MCP006",
                "TOOL005",
                "SCHEMA004",
                "SUPPLY001",
                "CAP003",
                "RES002",
                "PROMPT003",
                "PROMPT004",
            }
            <= finding_ids
        )
        self.assertFalse(payload["observations"]["tools_were_executed"])

    def test_v1_policy_and_reviewed_baseline_pass_together(self) -> None:
        completed = run_check(
            GOOD_SERVER,
            "json",
            "--config",
            str(ROOT / "examples" / "mcp-ci-policy.json"),
            "--baseline",
            str(ROOT / "examples" / "mcp-ci-baseline.json"),
        )

        payload = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertEqual(payload["findings"], [])
        self.assertTrue(payload["observations"]["policy"]["configured"])
        self.assertEqual(payload["observations"]["baseline"]["finding_count"], 0)

    def test_stdio_fixture_supports_documented_protocol_matrix(self) -> None:
        for version in ("2025-03-26", "2025-06-18", "2025-11-25"):
            with self.subTest(version=version):
                completed = run_check(
                    GOOD_SERVER,
                    "json",
                    "--protocol-version",
                    version,
                )
                payload = json.loads(completed.stdout)
                self.assertEqual(
                    completed.returncode, 0, completed.stderr + completed.stdout
                )
                self.assertEqual(payload["negotiated_protocol_version"], version)
                self.assertEqual(payload["findings"], [])

    def test_good_streamable_http_server_passes_without_leaking_session(self) -> None:
        server = McpHttpServer(("127.0.0.1", 0), GoodMcpHandler)
        server.quiet = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/mcp"
            completed = run_http_check(url)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        payload = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["observations"]["transport"], "http")
        self.assertEqual(payload["observations"]["discovered_tool_count"], 1)
        self.assertEqual(payload["observations"]["discovered_resource_count"], 1)
        self.assertEqual(
            payload["observations"]["discovered_resource_template_count"], 1
        )
        self.assertEqual(payload["observations"]["discovered_prompt_count"], 1)
        self.assertEqual(
            payload["observations"]["pagination_checks"]["resources"]["page_count"],
            2,
        )
        self.assertEqual(
            payload["observations"]["transport_checks"]["delete_status"], 204
        )
        for session_id in server.issued_session_ids:
            self.assertNotIn(session_id, completed.stdout)


if __name__ == "__main__":
    unittest.main()
