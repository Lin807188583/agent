import asyncio
from pathlib import Path
import sys
import unittest

from mcp_ci.transport import JsonRpcStdioClient


FIXTURE = Path(__file__).parent / "fixtures" / "rpc_fixture.py"


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = JsonRpcStdioClient([sys.executable, str(FIXTURE)], timeout=2)
        await self.client.start()

    async def asyncTearDown(self) -> None:
        await self.client.close()

    async def test_round_trip_returns_raw_json_rpc_response(self) -> None:
        response = await self.client.request("echo", {"hello": "world"})

        self.assertEqual(response["result"], {"hello": "world"})
        self.assertEqual(response["jsonrpc"], "2.0")

    async def test_concurrent_responses_are_correlated_by_id(self) -> None:
        slow, fast = await asyncio.gather(
            self.client.request("delayed", {"value": "slow", "delay": 0.05}),
            self.client.request("delayed", {"value": "fast", "delay": 0}),
        )

        self.assertEqual(slow["result"]["value"], "slow")
        self.assertEqual(fast["result"]["value"], "fast")

    async def test_protocol_noise_and_stderr_are_kept_separate(self) -> None:
        await self.client.request("emit_noise")
        await asyncio.sleep(0.02)

        self.assertIn("debug text accidentally written to stdout", self.client.protocol_noise)
        self.assertIn("fixture ready", self.client.stderr_lines)

    async def test_server_request_with_same_id_is_not_mistaken_for_response(self) -> None:
        response = await self.client.request("server_request_collision")

        self.assertEqual(response["result"]["kind"], "response")
        self.assertEqual(self.client.unsolicited_messages[0]["method"], "sampling/createMessage")

    async def test_diagnostic_evidence_is_bounded_and_auditable(self) -> None:
        client = JsonRpcStdioClient(
            [sys.executable, str(FIXTURE)],
            timeout=2,
            diagnostic_limit=2,
            diagnostic_text_limit=32,
        )
        await client.start()
        try:
            await client.request("diagnostic_flood")
            await asyncio.sleep(0.02)
        finally:
            await client.close()

        diagnostics = client.diagnostic_observations
        self.assertEqual(diagnostics["protocol_noise"]["total"], 5)
        self.assertEqual(diagnostics["protocol_noise"]["retained"], 2)
        self.assertTrue(diagnostics["protocol_noise"]["truncated"])
        self.assertEqual(diagnostics["stderr"]["total"], 6)
        self.assertEqual(diagnostics["stderr"]["retained"], 2)
        self.assertTrue(diagnostics["stderr"]["truncated"])
        self.assertEqual(diagnostics["unsolicited_messages"]["total"], 5)
        self.assertEqual(diagnostics["unsolicited_messages"]["retained"], 2)
        self.assertTrue(diagnostics["unsolicited_messages"]["truncated"])
        self.assertTrue(
            diagnostics["unsolicited_messages"]["content_summarized"]
        )
        self.assertTrue(all(len(line) <= 32 for line in client.protocol_noise))
        self.assertTrue(all(len(line) <= 32 for line in client.stderr_lines))
        self.assertNotIn("params", client.unsolicited_messages[0])
        self.assertEqual(
            client.unsolicited_messages[0]["method"], "sampling/createMessage"
        )


if __name__ == "__main__":
    unittest.main()
