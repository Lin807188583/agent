# MCP CI Demo Design

## Product boundary

The demo is a black-box checker for maintainers of local MCP servers and gateways. A maintainer gives the CLI a `stdio` launch command. The checker starts that command as a child process, speaks line-delimited JSON-RPC 2.0, performs the MCP initialization lifecycle, exercises only discovery methods advertised by the server's capabilities, and returns findings with stable rule IDs and CI-friendly exit codes.

Version 0.1 deliberately does not implement Streamable HTTP, OAuth, real tool execution, source-code scanning, an interactive dashboard, or model-based prompt-injection classification. Those belong in later versions. Not executing discovered tools is a safety boundary: a generic checker cannot know whether a tool has side effects merely from its name or annotations.

## Architecture

```text
CLI
  -> stdio subprocess transport
  -> JSON-RPC request correlation
  -> MCP lifecycle/discovery probe
  -> deterministic rule engine
  -> text or JSON reporter
  -> severity-based exit code
```

Checks are split into protocol findings and security-review findings. Protocol findings cover lifecycle, response correlation, JSON-RPC errors, negotiated protocol version, and `tools/list` result shape. Security-review findings cover duplicate or malformed tool names, missing descriptions, suspicious instructions in descriptions, schema mistakes, secret-like defaults, destructive-looking tools without a read-only annotation, and tool-manifest drift between two discovery calls.

## Teaching fixtures

The repository includes two zero-dependency MCP servers. `good_server.py` implements a stable, read-only tool contract and correct unknown-method errors. `bad_server.py` stays protocol-compatible enough to inspect but exposes ambiguous/destructive tools, a permissive or inconsistent schema, a secret-like default, suspicious instruction text, and a changing tool manifest. This lets a learner compare the same probe and report pipeline against a passing and failing target.

## Success criteria

- A fresh Python 3.11+ environment runs the demo without installing packages.
- The good fixture exits `0` at the default threshold.
- The bad fixture exits non-zero and emits stable finding IDs.
- Text and JSON output contain the same findings.
- Unit tests cover rules and exit policy; integration tests launch real child processes.
- The sample GitHub Actions workflow demonstrates CI use without publishing an action.
