# MCP Capability and Pagination Design

**Goal:** Extend the black-box MCP CI checker with safe discovery of `tools`, `resources`, `resource templates`, and `prompts`, including opaque-cursor pagination checks, without reading resources, resolving prompts, or executing tools.

**Scope:** v0.4 targets the MCP `2025-11-25` capability and pagination contracts. The probe performs only `initialize`, `notifications/initialized`, `ping`, list methods, and the existing unknown-method request. It never calls `tools/call`, `resources/read`, or `prompts/get`.

## Design decisions

1. **Capability-gated discovery.** A list method is sent only when its corresponding capability is present in the initialize result. A malformed capability value is still retained as evidence so rules can report it; it is not treated as permission to perform unrelated operations.
2. **Opaque cursors.** The probe stores each server-returned `nextCursor` verbatim and sends it back as `params.cursor`. It never parses, increments, normalizes, or logs cursor contents. Only a bounded number of pages (20) is requested.
3. **Bounded failure behavior.** Empty/malformed responses, repeated cursors, cursor cycles, and an exhausted page budget terminate that list flow and become deterministic findings. A malformed list response does not cause reads or calls as a fallback.
4. **Evidence without secrets.** Reports contain page counts, item counts, response shape summaries, and capability observations. Raw session IDs remain excluded; cursors are not copied into report evidence.
5. **Compatibility profile.** The requested `--protocol-version` remains the source of the initialize baseline. v0.4 adds no new profile selector; the list contracts are enabled for the negotiated response and documented against the latest `2025-11-25` profile.

## Evidence model

`ProbeEvidence` gains:

- `resources_list_pages` and `resource_templates_list_pages`;
- `prompts_list_pages`;
- `tools_list_pages` (the first and subsequent responses, replacing the implicit two snapshots while retaining the legacy fields);
- `pagination_observations` with per-flow page count, item count, termination reason, and shape errors;
- `capability_observations` containing only safe type/listChanged facts.

Each page response is retained internally for deterministic rule evaluation, but report observations summarize it rather than exposing cursor values.

## Rule contract

- `CAP001`: declared capability's list method failed or did not return a result object.
- `CAP002`: capability value is not an object.
- `CAP003`: `listChanged` is present but not boolean.
- `CAP004`: `listChanged` is declared while its base list method is unavailable.
- `PAGE001`: `nextCursor` is not a string.
- `PAGE002`: a cursor repeats or cycles.
- `PAGE003`: the maximum page count is reached while a cursor is still returned.
- `PAGE004`: entries in one flow are not consistently objects.
- `PAGE005`: a list result's collection field is not an array.

Existing tool contract rules continue to apply to the complete, concatenated tools snapshot. `SUPPLY001` compares the first and final complete snapshots when pagination yields more than one page.
