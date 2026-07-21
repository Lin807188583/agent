# MCP CI v0.3: Streamable HTTP Design

## Product boundary

Version 0.3 adds black-box Streamable HTTP checks to the existing `stdio` checker. A maintainer chooses exactly one target:

```text
mcp-ci check --stdio "python server.py"
mcp-ci check --http "https://example.com/mcp"
```

This is still a CI checker, not a gateway. It does not proxy traffic, discover OAuth metadata, accept bearer tokens, execute Tools, keep a background SSE listener alive, or test arbitrary side effects. The HTTP probe sends only lifecycle, ping, discovery, unknown-method and deliberately malformed transport requests.

The protocol baseline is the official MCP `2025-11-25` transport specification:

- [Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)

The implementation follows the current Streamable HTTP rules rather than the deprecated 2024 HTTP+SSE dual-endpoint transport.

## Alternatives considered

### A. Only send one initialize POST

This is small, but it proves little beyond endpoint reachability. It misses the rules that make HTTP transport difficult in practice: notification status, session propagation, protocol-version headers, GET/SSE behavior and Origin validation.

### B. Implement a full long-lived MCP Host

This would cover bidirectional server requests, resumability and multiple streams, but it would turn a CI probe into a stateful runtime and substantially enlarge timeout, cancellation and authentication concerns.

### C. Bounded black-box lifecycle probe — selected

The checker supports JSON and SSE responses to POST, closes a GET stream after inspecting its headers, and records deterministic HTTP observations. It provides useful compatibility/security evidence while keeping execution bounded and never calling discovered Tools.

## Architecture

```text
CLI target selector
  ├─ stdio command -> JsonRpcStdioClient
  └─ HTTP URL     -> JsonRpcHttpClient
                         ├─ URL/TLS policy
                         ├─ POST JSON-RPC
                         ├─ JSON response parser
                         └─ bounded SSE response parser
            -> shared lifecycle/discovery probe
            -> transport-specific evidence
            -> shared + HTTP rules
            -> text / JSON / JUnit / SARIF
```

The existing `ProbeEvidence` gains a transport name and a JSON-serializable `transport_observations` object. It never stores a raw session ID because reports and CI artifacts are an inappropriate place for session secrets. Only presence, length and character-validity are retained.

The HTTP client uses Python's standard-library `urllib` inside `asyncio.to_thread`. TLS certificate verification remains enabled. Plain HTTP is accepted only for loopback hosts, which supports local tests without silently allowing cleartext remote sessions. Redirects are not followed: a redirect changes the endpoint and trust boundary, so the checker reports it as the response it actually received.

## Probe sequence

1. POST a safe `ping` with `Origin: https://attacker.invalid`; a compliant endpoint returns `403`.
2. POST `initialize` with `Content-Type: application/json` and an `Accept` header listing both `application/json` and `text/event-stream`.
3. Capture the negotiated protocol version and, if present, `MCP-Session-Id` without adding the raw value to evidence.
4. POST `notifications/initialized`; a compliant endpoint accepts it with `202` and an empty body.
5. Run the same safe `ping`, capability-aware `tools/list` twice and unknown-method probe used for stdio.
6. GET the endpoint with `Accept: text/event-stream`, then close immediately after headers. Valid outcomes are `405` or a successful SSE response.
7. POST `ping` with an invalid `MCP-Protocol-Version`; the server must return `400`.
8. If a session was issued, POST `ping` without it; the expected hardening response is `400`.
9. DELETE the session as best-effort cleanup; `405` is explicitly allowed by the specification.

The probe never opens a persistent listener and never interprets disconnects as cancellation.

## HTTP rules

| ID | Severity | Contract |
|---|---|---|
| `HTTP001` | high | Invalid Origin must be rejected with 403 |
| `HTTP002` | high | Initialize POST must return a successful HTTP status |
| `HTTP003` | high | Request responses must use JSON or SSE content type |
| `HTTP004` | medium | Accepted notification must return 202 with no body |
| `HTTP005` | medium | GET must return SSE or 405 |
| `HTTP006` | medium | Invalid protocol-version header must return 400 |
| `HTTP007` | high | Issued session ID must contain visible ASCII only |
| `HTTP008` | medium | A session-using server should reject a missing session header with 400 |

`HTTP008` tests a protocol SHOULD, so it is medium rather than high. Session unpredictability cannot be proven from one value and is not claimed as a deterministic finding.

## Error handling and safety

- Invalid URL schemes, embedded credentials, missing hosts and non-loopback cleartext HTTP are operational errors (`2`).
- DNS, TLS and timeout failures are operational errors because no server behavior was observed reliably.
- HTTP error statuses are evidence, not transport exceptions.
- Bodies and SSE streams have a one-megabyte inspection limit.
- Response parsing keeps unsolicited JSON-RPC messages separate from the matching response.
- Raw session IDs and response authorization headers never enter report output.

## Success criteria

- All v0.2 stdio behavior and 29 tests remain compatible.
- A zero-dependency local HTTP teaching Server passes at the default threshold.
- The client accepts both JSON and bounded SSE POST responses.
- Origin, content type, notification, GET, version and session failures produce stable rule IDs.
- CLI and composite Action enforce exactly one of `stdio` or `http`.
- No discovered Tool is executed and no session ID appears in JSON/SARIF artifacts.
