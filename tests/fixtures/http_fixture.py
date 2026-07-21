"""In-process Streamable HTTP fixture with JSON and SSE response modes."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any, cast


GOOD_TOOL = {
    "name": "read_note",
    "description": "Read a note by public identifier.",
    "inputSchema": {
        "type": "object",
        "properties": {"note_id": {"type": "string"}},
        "required": ["note_id"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": True},
}

GOOD_RESOURCE = {
    "uri": "memo://one",
    "name": "One",
    "mimeType": "text/plain",
}
GOOD_RESOURCE_TEMPLATE = {
    "uriTemplate": "memo://{id}",
    "name": "Memo",
}
GOOD_PROMPT = {"name": "summarize", "description": "Summarize a note."}


class FixtureServer(ThreadingHTTPServer):
    mode: str
    received: list[dict[str, Any]]
    session_id: str


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def fixture(self) -> FixtureServer:
        return cast(FixtureServer, self.server)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _record(self, message: object | None = None) -> None:
        self.fixture.received.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": {key.lower(): value for key, value in self.headers.items()},
                "message": message,
            }
        )

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, status: int, payload: object, *, session: bool = False) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if session:
            self.send_header("MCP-Session-Id", self.fixture.session_id)
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, payloads: list[object], *, session: bool = False) -> None:
        chunks = []
        for index, payload in enumerate(payloads, start=1):
            encoded = json.dumps(payload, separators=(",", ":"))
            chunks.append(f"id: fixture-{index}\ndata: {encoded}\n\n")
        body = "".join(chunks).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if session:
            self.send_header("MCP-Session-Id", self.fixture.session_id)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        message = json.loads(raw) if raw else None
        self._record(message)

        if self.path == "/redirect":
            self.send_response(307)
            self.send_header("Location", "/mcp")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path != "/mcp":
            self._empty(404)
            return
        if self.headers.get("Origin") == "https://attacker.invalid":
            self._empty(403)
            return

        assert isinstance(message, dict)
        method = message.get("method")
        request_id = message.get("id")
        if method != "initialize":
            protocol = self.headers.get("MCP-Protocol-Version")
            if protocol != "2025-11-25":
                self._empty(400)
                return
            if self.headers.get("MCP-Session-Id") != self.fixture.session_id:
                self._empty(400)
                return

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "http-fixture", "version": "1.0"},
                },
            }
            if self.fixture.mode == "sse":
                collision = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "sampling/createMessage",
                    "params": {},
                }
                self._sse([collision, response], session=True)
            else:
                self._json(200, response, session=True)
            return
        if method == "notifications/initialized":
            self._empty(202)
            return
        if method == "ping":
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})
            return
        if method == "tools/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"tools": []} if cursor == "tool-page-2" else {"tools": [GOOD_TOOL], "nextCursor": "tool-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        if method == "resources/list":
            cursor = message.get("params", {}).get("cursor")
            if self.fixture.mode == "bad-cursor":
                result = {"resources": [GOOD_RESOURCE, "not-an-object"], "nextCursor": 42}
            elif self.fixture.mode == "repeated-cursor":
                result = {"resources": [], "nextCursor": "same-cursor"}
            else:
                result = {"resources": []} if cursor == "resource-page-2" else {"resources": [GOOD_RESOURCE], "nextCursor": "resource-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        if method == "resources/templates/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"resourceTemplates": []} if cursor == "template-page-2" else {"resourceTemplates": [GOOD_RESOURCE_TEMPLATE], "nextCursor": "template-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        if method == "prompts/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"prompts": []} if cursor == "prompt-page-2" else {"prompts": [GOOD_PROMPT], "nextCursor": "prompt-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        self._json(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            },
        )

    def do_GET(self) -> None:
        self._record()
        if self.path != "/mcp":
            self._empty(404)
            return
        if self.headers.get("MCP-Protocol-Version") != "2025-11-25":
            self._empty(400)
            return
        if self.headers.get("MCP-Session-Id") != self.fixture.session_id:
            self._empty(400)
            return
        self._empty(405)

    def do_DELETE(self) -> None:
        self._record()
        if self.headers.get("MCP-Session-Id") != self.fixture.session_id:
            self._empty(404)
            return
        self._empty(204)


class RunningHttpFixture:
    def __init__(self, mode: str = "json") -> None:
        self.server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
        self.server.mode = mode
        self.server.received = []
        self.server.session_id = (
            "invalid fixture session" if mode == "invalid-session" else "fixture-session-4f793f4a"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/mcp"

    def __enter__(self) -> "RunningHttpFixture":
        self.thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
