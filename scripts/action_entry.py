"""Safe GitHub composite-action entry point.

Inputs arrive through environment variables instead of being interpolated into
the action shell script.
"""

from __future__ import annotations

import os

from mcp_ci.cli import main


def target_arguments() -> list[str]:
    stdio = os.environ.get("MCP_CI_STDIO", "").strip()
    http = os.environ.get("MCP_CI_HTTP", "").strip()
    if bool(stdio) == bool(http):
        raise SystemExit("set exactly one action input: stdio or http")
    return ["--stdio", stdio] if stdio else ["--http", http]


def build_arguments() -> list[str]:
    arguments = [
        "check",
        *target_arguments(),
        "--fail-on",
        os.environ.get("MCP_CI_FAIL_ON", "medium"),
        "--protocol-version",
        os.environ.get("MCP_CI_PROTOCOL_VERSION", "2025-11-25"),
        "--timeout",
        os.environ.get("MCP_CI_TIMEOUT", "5"),
        "--total-timeout",
        os.environ.get("MCP_CI_TOTAL_TIMEOUT", "60"),
        "--format",
        os.environ.get("MCP_CI_FORMAT", "text"),
    ]
    for option, environment_name in (
        ("--config", "MCP_CI_CONFIG"),
        ("--baseline", "MCP_CI_BASELINE"),
        ("--output", "MCP_CI_OUTPUT"),
    ):
        value = os.environ.get(environment_name, "").strip()
        if value:
            arguments.extend([option, value])
    return arguments


if __name__ == "__main__":
    raise SystemExit(main(build_arguments()))
