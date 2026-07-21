"""Minimal well-behaved MCP server used by probe tests."""

from __future__ import annotations

import json
import sys


initialized = False


READ_NOTE = {
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


def respond(request_id: object, *, result: object = None, error: object = None) -> None:
    message = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        message["error"] = error
    else:
        message["result"] = result
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    global initialized
    sys.stderr.write("mcp fixture ready\n")
    sys.stderr.flush()
    for raw_line in sys.stdin:
        message = json.loads(raw_line)
        method = message.get("method")
        if "id" not in message:
            if method == "notifications/initialized":
                initialized = True
            continue
        request_id = message["id"]
        if method == "initialize":
            params = message.get("params", {})
            respond(
                request_id,
                result={
                    "protocolVersion": params.get("protocolVersion", "2025-11-25"),
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "probe-fixture", "version": "1.0.0"},
                },
            )
        elif method == "ping" and initialized:
            respond(request_id, result={})
        elif method == "tools/list" and initialized:
            if message.get("params", {}).get("cursor") == "tool-page-2":
                respond(request_id, result={"tools": []})
            else:
                respond(request_id, result={"tools": [READ_NOTE], "nextCursor": "tool-page-2"})
        elif method == "resources/list" and initialized:
            if message.get("params", {}).get("cursor") == "resource-page-2":
                respond(request_id, result={"resources": []})
            else:
                respond(
                    request_id,
                    result={
                        "resources": [{"uri": "memo://one", "name": "One", "mimeType": "text/plain"}],
                        "nextCursor": "resource-page-2",
                    },
                )
        elif method == "resources/templates/list" and initialized:
            if message.get("params", {}).get("cursor") == "template-page-2":
                respond(request_id, result={"resourceTemplates": []})
            else:
                respond(
                    request_id,
                    result={
                        "resourceTemplates": [{"uriTemplate": "memo://{id}", "name": "Memo"}],
                        "nextCursor": "template-page-2",
                    },
                )
        elif method == "prompts/list" and initialized:
            if message.get("params", {}).get("cursor") == "prompt-page-2":
                respond(request_id, result={"prompts": []})
            else:
                respond(
                    request_id,
                    result={"prompts": [{"name": "summarize", "description": "Summarize a note."}], "nextCursor": "prompt-page-2"},
                )
        else:
            respond(
                request_id,
                error={"code": -32601, "message": "Method not found"},
            )


if __name__ == "__main__":
    main()
