"""Minimal MCP 2025-11-25 Streamable HTTP teaching server.

The server binds to loopback only, validates Origin, uses opaque sessions, and
exposes discovery metadata without implementing any real Tool execution.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import sys
import threading
from typing import Any, cast


PROTOCOL_VERSION = "2025-11-25"
MAX_REQUEST_BODY = 1024 * 1024
ALLOWED_ORIGINS = {"http://localhost", "http://127.0.0.1"}

READ_NOTE_TOOL = {
    "name": "read_note",
    "description": "Read a note by its public identifier.",
    "inputSchema": {
        "type": "object",
        "properties": {"note_id": {"type": "string", "minLength": 1}},
        "required": ["note_id"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": True},
}

RESOURCE = {
    "uri": "memo://one",
    "name": "One",
    "mimeType": "text/plain",
}
RESOURCE_TEMPLATE = {"uriTemplate": "memo://{id}", "name": "Memo"}
PROMPT = {"name": "summarize", "description": "Summarize a note."}


class McpHttpServer(ThreadingHTTPServer):
    """Loopback teaching server with synchronized in-memory session state."""

    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sessions: set[str] = set()
        self.initialized_sessions: set[str] = set()
        self.issued_session_ids: list[str] = []
        self.session_lock = threading.Lock()
        self.quiet = False

    def issue_session(self) -> str:
        session_id = secrets.token_urlsafe(32)
        with self.session_lock:
            self.sessions.add(session_id)
            self.issued_session_ids.append(session_id)
        return session_id

    def has_session(self, session_id: str) -> bool:
        with self.session_lock:
            return session_id in self.sessions

    def mark_initialized(self, session_id: str) -> None:
        with self.session_lock:
            self.initialized_sessions.add(session_id)

    def delete_session(self, session_id: str) -> bool:
        with self.session_lock:
            if session_id not in self.sessions:
                return False
            self.sessions.remove(session_id)
            self.initialized_sessions.discard(session_id)
            return True


class GoodMcpHandler(BaseHTTPRequestHandler):
    """One `/mcp` endpoint supporting POST, GET and session cleanup."""

    protocol_version = "HTTP/1.1"
    server_version = "McpCiTeachingServer/1.0"

    @property
    def mcp_server(self) -> McpHttpServer:
        return cast(McpHttpServer, self.server)

    def log_message(self, format: str, *args: object) -> None:
        if not self.mcp_server.quiet:
            sys.stderr.write("http server: " + (format % args) + "\n")

    def _empty(self, status: int, *, close: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()

    def _json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> None:
        body = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if session_id is not None:
            self.send_header("MCP-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _origin_is_valid(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None or origin in ALLOWED_ORIGINS:
            return True
        self._empty(403, close=True)
        return False

    def _is_mcp_path(self) -> bool:
        if self.path == "/mcp":
            return True
        self._empty(404)
        return False

    def _read_message(self) -> dict[str, Any] | None:
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if media_type.lower() != "application/json":
            self._empty(415)
            return None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._empty(400)
            return None
        if length < 1 or length > MAX_REQUEST_BODY:
            self._empty(413 if length > MAX_REQUEST_BODY else 400)
            return None
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._empty(400)
            return None
        if not isinstance(message, dict):
            self._empty(400)
            return None
        return message

    def _validated_session(self) -> str | None:
        """Validate transport continuity; a session is never authentication."""

        if self.headers.get("MCP-Protocol-Version") != PROTOCOL_VERSION:
            self._empty(400)
            return None
        session_id = self.headers.get("MCP-Session-Id")
        if session_id is None:
            self._empty(400)
            return None
        if not self.mcp_server.has_session(session_id):
            self._empty(404)
            return None
        return session_id

    def do_POST(self) -> None:
        if not self._origin_is_valid() or not self._is_mcp_path():
            return
        message = self._read_message()
        if message is None:
            return
        method = message.get("method")
        request_id = message.get("id")

        if method == "initialize":
            session_id = self.mcp_server.issue_session()
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"listChanged": False},
                            "prompts": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "good-http-learning-server",
                            "version": "1.0.0",
                        },
                    },
                },
                session_id=session_id,
            )
            return

        session_id = self._validated_session()
        if session_id is None:
            return
        if not isinstance(method, str):
            self._empty(202)
            return
        if "id" not in message:
            if method == "notifications/initialized":
                self.mcp_server.mark_initialized(session_id)
            self._empty(202)
            return
        if method == "ping":
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})
            return
        if method == "tools/list":
            cursor = message.get("params", {}).get("cursor")
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": []}
                    if cursor == "tool-page-2"
                    else {"tools": [READ_NOTE_TOOL], "nextCursor": "tool-page-2"},
                },
            )
            return
        if method == "resources/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"resources": []} if cursor == "resource-page-2" else {"resources": [RESOURCE], "nextCursor": "resource-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        if method == "resources/templates/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"resourceTemplates": []} if cursor == "template-page-2" else {"resourceTemplates": [RESOURCE_TEMPLATE], "nextCursor": "template-page-2"}
            self._json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
            return
        if method == "prompts/list":
            cursor = message.get("params", {}).get("cursor")
            result = {"prompts": []} if cursor == "prompt-page-2" else {"prompts": [PROMPT], "nextCursor": "prompt-page-2"}
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
        if not self._origin_is_valid() or not self._is_mcp_path():
            return
        if self._validated_session() is None:
            return
        self.send_response(405)
        self.send_header("Allow", "POST, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self) -> None:
        if not self._origin_is_valid() or not self._is_mcp_path():
            return
        session_id = self._validated_session()
        if session_id is None:
            return
        if self.mcp_server.delete_session(session_id):
            self._empty(204)
        else:
            self._empty(404)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = McpHttpServer(("127.0.0.1", args.port), GoodMcpHandler)
    print(
        f"MCP Streamable HTTP demo listening on http://127.0.0.1:{server.server_port}/mcp",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
