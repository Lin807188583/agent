"""A tiny, well-behaved MCP stdio server for learning and CI smoke tests.

It intentionally implements only the methods used by the safe discovery probe.
"""

from __future__ import annotations

import json
import sys
from typing import Any


initialized = False


TOOLS = [
    {
        "name": "read_note",
        "description": "Read a public note by its stable identifier. This tool has no side effects.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "note_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 80,
                    "description": "Public note identifier, not a filesystem path.",
                }
            },
            "required": ["note_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    }
]


def send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(request_id: Any, value: Any) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "result": value})


def error(request_id: Any, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def main() -> None:
    global initialized
    print("good_server: logs belong on stderr", file=sys.stderr, flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            error(None, -32700, "Parse error")
            continue
        method = request.get("method")
        if "id" not in request:
            if method == "notifications/initialized":
                initialized = True
            continue
        request_id = request["id"]
        if method == "initialize":
            params = request.get("params", {})
            result(
                request_id,
                {
                    "protocolVersion": params.get("protocolVersion", "2025-11-25"),
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "good-learning-server", "version": "1.0.0"},
                },
            )
        elif not initialized:
            error(request_id, -32002, "Server is not initialized")
        elif method == "ping":
            result(request_id, {})
        elif method == "tools/list":
            cursor = request.get("params", {}).get("cursor")
            result(request_id, {"tools": []} if cursor == "tool-page-2" else {"tools": TOOLS, "nextCursor": "tool-page-2"})
        elif method == "resources/list":
            cursor = request.get("params", {}).get("cursor")
            result(request_id, {"resources": []} if cursor == "resource-page-2" else {"resources": [{"uri": "memo://one", "name": "One", "mimeType": "text/plain"}], "nextCursor": "resource-page-2"})
        elif method == "resources/templates/list":
            cursor = request.get("params", {}).get("cursor")
            result(request_id, {"resourceTemplates": []} if cursor == "template-page-2" else {"resourceTemplates": [{"uriTemplate": "memo://{id}", "name": "Memo"}], "nextCursor": "template-page-2"})
        elif method == "prompts/list":
            cursor = request.get("params", {}).get("cursor")
            result(request_id, {"prompts": []} if cursor == "prompt-page-2" else {"prompts": [{"name": "summarize", "description": "Summarize a note."}], "nextCursor": "prompt-page-2"})
        else:
            error(request_id, -32601, "Method not found")


if __name__ == "__main__":
    main()
