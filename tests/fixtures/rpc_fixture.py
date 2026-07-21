"""Tiny line-delimited JSON-RPC process used by transport tests."""

from __future__ import annotations

import json
import sys
import threading
import time


write_lock = threading.Lock()
workers: list[threading.Thread] = []


def write_message(message: object) -> None:
    with write_lock:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def handle(message: dict[str, object]) -> None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if method == "echo":
        write_message({"jsonrpc": "2.0", "id": request_id, "result": params})
    elif method == "delayed":
        assert isinstance(params, dict)
        time.sleep(float(params.get("delay", 0)))
        write_message(
            {"jsonrpc": "2.0", "id": request_id, "result": {"value": params.get("value")}}
        )
    elif method == "emit_noise":
        with write_lock:
            sys.stdout.write("debug text accidentally written to stdout\n")
            sys.stdout.flush()
        write_message({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "diagnostic_flood":
        for index in range(5):
            with write_lock:
                sys.stdout.write(f"noise-{index}-{'x' * 64}\n")
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": f"server-{index}",
                            "method": "sampling/createMessage",
                            "params": {"untrusted": "y" * 64},
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                sys.stdout.flush()
            sys.stderr.write(f"stderr-{index}-{'z' * 64}\n")
            sys.stderr.flush()
        write_message({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "server_request_collision":
        write_message(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "sampling/createMessage",
                "params": {},
            }
        )
        write_message({"jsonrpc": "2.0", "id": request_id, "result": {"kind": "response"}})
    else:
        write_message(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )


def main() -> None:
    sys.stderr.write("fixture ready\n")
    sys.stderr.flush()
    for raw_line in sys.stdin:
        message = json.loads(raw_line)
        if "id" not in message:
            continue
        worker = threading.Thread(target=handle, args=(message,), daemon=True)
        worker.start()
        workers.append(worker)
    for worker in workers:
        worker.join(timeout=1)


if __name__ == "__main__":
    main()
