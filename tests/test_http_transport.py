import unittest

from mcp_ci.http_transport import JsonRpcHttpClient, validate_http_url
from tests.fixtures.http_fixture import RunningHttpFixture


INITIALIZE_PARAMS = {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": {"name": "transport-test", "version": "1.0"},
}


class UrlValidationTests(unittest.TestCase):
    def test_https_and_loopback_http_are_allowed(self) -> None:
        self.assertEqual(
            validate_http_url("https://mcp.example.com/mcp"),
            "https://mcp.example.com/mcp",
        )
        self.assertEqual(
            validate_http_url("http://127.0.0.1:8123/mcp"),
            "http://127.0.0.1:8123/mcp",
        )

    def test_remote_cleartext_and_embedded_credentials_are_rejected(self) -> None:
        invalid = [
            "http://mcp.example.com/mcp",
            "https://user:password@mcp.example.com/mcp",
            "file:///tmp/mcp.sock",
            "https:///missing-host",
        ]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_http_url(url)


class HttpClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_response_and_session_headers(self) -> None:
        with RunningHttpFixture("json") as fixture:
            client = JsonRpcHttpClient(fixture.url, timeout=2)

            initialized = await client.request("initialize", INITIALIZE_PARAMS)
            await client.notify("notifications/initialized")
            ping = await client.request("ping")

        self.assertEqual(initialized["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(ping["result"], {})
        self.assertEqual(client.session_id, "fixture-session-4f793f4a")
        notification = fixture.server.received[1]
        self.assertEqual(
            notification["headers"]["mcp-session-id"],
            "fixture-session-4f793f4a",
        )
        self.assertEqual(
            notification["headers"]["mcp-protocol-version"], "2025-11-25"
        )
        self.assertEqual(client.last_exchange.status, 200)

    async def test_sse_uses_response_shape_not_colliding_server_request(self) -> None:
        with RunningHttpFixture("sse") as fixture:
            client = JsonRpcHttpClient(fixture.url, timeout=2)

            initialized = await client.request("initialize", INITIALIZE_PARAMS)

        self.assertIn("result", initialized)
        self.assertEqual(
            client.unsolicited_messages[0]["method"], "sampling/createMessage"
        )

    async def test_redirect_is_observed_and_not_followed(self) -> None:
        with RunningHttpFixture() as fixture:
            redirect_url = fixture.url.replace("/mcp", "/redirect")
            client = JsonRpcHttpClient(redirect_url, timeout=2)

            response = await client.request("initialize", INITIALIZE_PARAMS)

        self.assertEqual(response, {})
        self.assertEqual(client.last_exchange.status, 307)
        self.assertEqual(len(fixture.server.received), 1)


if __name__ == "__main__":
    unittest.main()
