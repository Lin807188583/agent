from pathlib import Path
import json
import sys
import unittest

from mcp_ci.probe import _safe_lifecycle, run_http_probe, run_stdio_probe
from mcp_ci.rules import build_report
from tests.fixtures.http_fixture import RunningHttpFixture


FIXTURE = Path(__file__).parent / "fixtures" / "mcp_fixture.py"


class PagedClient:
    protocol_noise: list[str] = []
    unsolicited_messages: list[dict[str, object]] = []

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    async def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        self.calls.append((method, params))
        request_id = len(self.calls)
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"listChanged": True},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "paged", "version": "1.0"},
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "mcp-ci/unknown-method-probe":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        pages: dict[str, tuple[str, str, list[dict[str, object]]]] = {
            "tools/list": ("tools", "tool-next", [{"name": "read_note"}]),
            "resources/list": (
                "resources",
                "resource-next",
                [{"uri": "memo://one", "name": "One"}],
            ),
            "resources/templates/list": (
                "resourceTemplates",
                "template-next",
                [{"uriTemplate": "memo://{id}", "name": "Memo"}],
            ),
            "prompts/list": (
                "prompts",
                "prompt-next",
                [{"name": "summarize"}],
            ),
        }
        if method in pages:
            item_key, cursor, first_page = pages[method]
            if params is None:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {item_key: first_page, "nextCursor": cursor},
                }
            assert params == {"cursor": cursor}
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {item_key: [{**first_page[0], "page": 2}]},
            }
        raise AssertionError(f"unexpected method: {method}")

    async def notify(
        self, method: str, params: dict[str, object] | None = None
    ) -> None:
        self.calls.append((method, params))


class RepeatingPromptCursorClient(PagedClient):
    async def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        if method != "prompts/list":
            return await super().request(method, params)
        self.calls.append((method, params))
        return {
            "jsonrpc": "2.0",
            "id": len(self.calls),
            "result": {"prompts": [], "nextCursor": "same-opaque-cursor"},
        }


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_safe_lifecycle_discovers_declared_capabilities_with_opaque_cursors(self) -> None:
        client = PagedClient()

        responses = await _safe_lifecycle(client, "2025-11-25")

        self.assertEqual(len(responses["tools_list_pages"]), 2)
        self.assertEqual(len(responses["resources_list_pages"]), 2)
        self.assertEqual(len(responses["resource_templates_list_pages"]), 2)
        self.assertEqual(len(responses["prompts_list_pages"]), 2)
        self.assertIn(("tools/list", {"cursor": "tool-next"}), client.calls)
        self.assertIn(("resources/list", {"cursor": "resource-next"}), client.calls)
        methods = [method for method, _ in client.calls]
        self.assertNotIn("tools/call", methods)
        self.assertNotIn("resources/read", methods)
        self.assertNotIn("prompts/get", methods)

    async def test_safe_lifecycle_stops_on_a_repeated_cursor(self) -> None:
        client = RepeatingPromptCursorClient()

        responses = await _safe_lifecycle(client, "2025-11-25")

        observation = responses["pagination_observations"]["prompts"]
        self.assertEqual(observation["termination"], "repeated-cursor")
        self.assertEqual(observation["page_count"], 2)

    async def test_probe_runs_safe_lifecycle_and_discovery(self) -> None:
        evidence = await run_stdio_probe(
            [sys.executable, str(FIXTURE)],
            target="probe-fixture",
            requested_protocol_version="2025-11-25",
            timeout=2,
        )

        self.assertEqual(evidence.negotiated_protocol_version, "2025-11-25")
        self.assertEqual(evidence.server_info["name"], "probe-fixture")
        self.assertEqual(evidence.first_tools[0]["name"], "read_note")
        self.assertEqual(evidence.first_tools, evidence.second_tools)
        self.assertEqual(len(evidence.tools_list_pages), 2)
        self.assertEqual(len(evidence.resources_list_pages), 2)
        self.assertEqual(len(evidence.resource_templates_list_pages), 2)
        self.assertEqual(len(evidence.prompts_list_pages), 2)
        self.assertEqual(evidence.unknown_method_response["error"]["code"], -32601)
        self.assertIn("mcp fixture ready", evidence.stderr_lines)
        serialized = json.dumps(build_report(evidence).to_dict())
        self.assertNotIn("tool-page-2", serialized)
        self.assertNotIn("resource-page-2", serialized)

    async def test_http_probe_records_sanitized_transport_evidence(self) -> None:
        with RunningHttpFixture() as fixture:
            evidence = await run_http_probe(
                fixture.url,
                target=fixture.url,
                requested_protocol_version="2025-11-25",
                timeout=2,
            )

        observations = evidence.transport_observations
        self.assertEqual(evidence.transport, "http")
        self.assertEqual(evidence.server_info["name"], "http-fixture")
        self.assertEqual(evidence.first_tools[0]["name"], "read_note")
        self.assertEqual(observations["origin_status"], 403)
        self.assertEqual(observations["notification_status"], 202)
        self.assertEqual(observations["get_status"], 405)
        self.assertEqual(observations["invalid_protocol_status"], 400)
        self.assertEqual(observations["missing_session_status"], 400)
        self.assertEqual(observations["delete_status"], 204)
        self.assertTrue(observations["session_id_issued"])
        self.assertNotIn(
            "fixture-session-4f793f4a",
            json.dumps(observations),
            "raw session IDs must never enter report evidence",
        )
        serialized = json.dumps(build_report(evidence).to_dict())
        self.assertNotIn("resource-page-2", serialized)
        self.assertNotIn("template-page-2", serialized)
        methods = [
            request["message"].get("method")
            for request in fixture.server.received
            if isinstance(request["message"], dict)
        ]
        self.assertNotIn("tools/call", methods)
        self.assertNotIn("resources/read", methods)
        self.assertNotIn("prompts/get", methods)

    async def test_invalid_session_id_becomes_a_finding_not_a_header_error(self) -> None:
        with RunningHttpFixture("invalid-session") as fixture:
            evidence = await run_http_probe(
                fixture.url,
                target=fixture.url,
                timeout=2,
            )

        report = build_report(evidence)
        ids = {finding.rule_id for finding in report.findings}
        serialized = json.dumps(report.to_dict())
        self.assertIn("HTTP007", ids)
        self.assertNotIn("invalid fixture session", serialized)

    async def test_http_bad_cursor_is_reported_without_reading_resources(self) -> None:
        with RunningHttpFixture("bad-cursor") as fixture:
            evidence = await run_http_probe(fixture.url, target=fixture.url, timeout=2)

        report = build_report(evidence)
        ids = {finding.rule_id for finding in report.findings}
        self.assertTrue({"CAP001", "PAGE001", "PAGE004"} <= ids)
        methods = [
            request["message"].get("method")
            for request in fixture.server.received
            if isinstance(request["message"], dict)
        ]
        self.assertNotIn("resources/read", methods)


if __name__ == "__main__":
    unittest.main()
