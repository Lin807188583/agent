# MCP CI Rule Catalog

Rule IDs are the stable interface used by JSON, JUnit, SARIF, severity overrides, disabled-rule controls, and suppressions. IDs are not reused for different semantics.

## Lifecycle and JSON-RPC

| ID | Default | Meaning |
|---|---|---|
| `MCP001` | high | initialize did not return an MCP result |
| `MCP002` | high | stdio stdout contains non-protocol data |
| `MCP003` | high | negotiated protocol version is missing |
| `MCP004` | medium | negotiated version differs from the requested baseline |
| `MCP005` | medium | ping failed after initialization |
| `MCP006` | medium | unknown method did not return JSON-RPC `-32601` |
| `MCP007` | high | `tools/list` result lacks a tools array |
| `RPC001` | high | response lacks `jsonrpc: "2.0"` |
| `RPC002` | high | response id/result/error envelope is ambiguous |
| `RPC003` | high | error code/message types are malformed |

## Capability and pagination

| ID | Default | Meaning |
|---|---|---|
| `CAP001` | high | declared capability has no complete list method |
| `CAP002` | high | capabilities or a capability value is not an object |
| `CAP003` | medium | `listChanged` is present but not boolean |
| `CAP004` | medium | `listChanged` is declared without a usable base list |
| `PAGE001` | high | `nextCursor` is not a string |
| `PAGE002` | high | cursor repeats or cycles |
| `PAGE003` | high | cursor continues beyond the 20-page inspection limit |
| `PAGE004` | high | list entries are not objects |
| `PAGE005` | high | list collection field is not an array |

## Tool and schema metadata

| ID | Default | Meaning |
|---|---|---|
| `TOOL001` | high | Tool entry is not an object |
| `TOOL002` | high | Tool names are duplicated |
| `TOOL003` | medium | Tool name is missing or non-portable |
| `TOOL004` | low | Tool description is missing |
| `TOOL005` | high | Tool description has suspicious instruction-like text |
| `SCHEMA001` | high | inputSchema is not an object schema |
| `SCHEMA002` | high | schema properties is not an object |
| `SCHEMA003` | medium | required references undeclared properties |
| `SCHEMA004` | high | schema contains a secret-like default |
| `SCHEMA005` | low | schema accepts undeclared parameters |
| `SEC001` | medium | mutating-looking Tool lacks an explicit read-only hint |
| `SUPPLY001` | medium | two Tool snapshots drift during one probe |

`TOOL005` and `SEC001` are review signals. Tool annotations and names are untrusted metadata, not proof of implementation behavior.

## Resources and Prompts

| ID | Default | Meaning |
|---|---|---|
| `RES001` | high | Resource lacks an absolute URI or non-empty name |
| `RES002` | high | Resource URIs are duplicated |
| `RES003` | medium | optional Resource fields have invalid types |
| `RESTPL001` | high | Resource Template required fields are malformed |
| `RESTPL002` | medium | Resource Template metadata is malformed or duplicated |
| `PROMPT001` | medium | Prompt name is missing or non-portable |
| `PROMPT002` | high | Prompt names are duplicated |
| `PROMPT003` | high/medium | Prompt arguments or optional metadata are malformed |
| `PROMPT004` | high | Prompt description has suspicious instruction-like text |

The checker never resolves these entries. Resource duplicate evidence uses indexes rather than raw URIs.

## Streamable HTTP

| ID | Default | Meaning |
|---|---|---|
| `HTTP001` | high | invalid Origin is not rejected with 403 |
| `HTTP002` | high | initialize POST is not successful |
| `HTTP003` | high | successful response is not valid JSON or SSE MCP |
| `HTTP004` | medium | notification does not return 202 with an empty body |
| `HTTP005` | medium | GET is neither SSE nor 405 |
| `HTTP006` | medium | invalid protocol header is not rejected with 400 |
| `HTTP007` | high | session ID is empty or contains non-visible ASCII |
| `HTTP008` | medium | missing session header is not rejected after session issue |

## Repository policy

| ID | Default | Meaning |
|---|---|---|
| `POL001` | high | negotiated protocol is outside the allowed set |
| `POL002` | high | required capability is missing |
| `POL003` | high | required Tool is missing |
| `POL004` | critical | Tool matches a forbidden pattern |
| `POL005` | high | Tool count exceeds the project maximum |
| `POL006` | high | policy-selected Tool is not explicitly read-only |

## Reviewed baseline

| ID | Default | Meaning |
|---|---|---|
| `BASE001` | high | protocol differs from the baseline |
| `BASE002` | high | capability set differs from the baseline |
| `BASE003` | high | Tool manifest differs from the baseline |
| `BASE004` | medium | Resource/Template manifest differs from the baseline |
| `BASE005` | medium | Prompt manifest differs from the baseline |

Baseline and policy findings can be severity-overridden, disabled, or suppressed like built-in rules. Treat each control as code-reviewed risk policy.
