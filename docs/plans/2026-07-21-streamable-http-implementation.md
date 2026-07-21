# Streamable HTTP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add bounded MCP 2025-11-25 Streamable HTTP compatibility and security checks without changing the checker into a gateway.

**Architecture:** Add a standard-library HTTP JSON-RPC client beside the stdio client, extract lifecycle probing into a reusable client-oriented function, and attach HTTP-only observations to the existing report/rule pipeline. The CLI selects exactly one transport while reporters and suppression remain transport-neutral.

**Tech Stack:** Python 3.11+, `asyncio`, `urllib.request`, `http.server`, `unittest`, JSON-RPC 2.0, SSE, GitHub composite Actions.

---

### Task 1: Define URL and HTTP response behavior

**Files:**
- Create: `src/mcp_ci/http_transport.py`
- Create: `tests/test_http_transport.py`

**Steps:**

1. Write failing tests for HTTPS acceptance, loopback HTTP acceptance, remote HTTP rejection, credential rejection and redirect non-following.
2. Write failing parser tests for `application/json`, SSE events, matching request IDs and bounded bodies.
3. Run `PYTHONPATH=src python3.12 -m unittest tests.test_http_transport -v`; expect import/test failures.
4. Implement `validate_http_url`, `HttpExchange` and `JsonRpcHttpClient` with standard-library networking.
5. Re-run the focused tests; expect pass.

### Task 2: Share the safe probe lifecycle

**Files:**
- Modify: `src/mcp_ci/probe.py`
- Modify: `tests/test_probe.py`
- Create: `tests/fixtures/http_fixture.py`

**Steps:**

1. Add failing tests that HTTP probing negotiates a version, forwards a session internally, records sanitized observations and never calls Tools.
2. Extract the existing initialize/ping/tools/unknown-method sequence into a private client-neutral coroutine.
3. Implement `run_http_probe()` around the Origin, lifecycle, GET, invalid-version, missing-session and DELETE sequence.
4. Run focused probe tests; expect stdio and HTTP cases to pass.

### Task 3: Add deterministic HTTP rules

**Files:**
- Modify: `src/mcp_ci/rules.py`
- Modify: `tests/test_rules.py`
- Modify: `tests/test_config.py`

**Steps:**

1. Add failing synthetic-evidence tests for `HTTP001` through `HTTP008`.
2. Register all eight stable IDs in `KNOWN_RULE_IDS`.
3. Implement rule evaluation using only sanitized transport observations.
4. Verify an HTTP rule can be suppressed through the existing strict configuration.
5. Run rule/config tests; expect pass.

### Task 4: Expose HTTP through CLI and Action

**Files:**
- Modify: `src/mcp_ci/cli.py`
- Modify: `scripts/action_entry.py`
- Modify: `action.yml`
- Modify: `tests/test_cli.py`

**Steps:**

1. Add failing parser/CLI tests requiring exactly one of `--stdio` or `--http`.
2. Dispatch `--http` to `run_http_probe()` while preserving report/output/exit behavior.
3. Add optional `http` Action input, make `stdio` optional, and enforce exclusivity in Python rather than shell.
4. Run CLI tests and manually smoke-test the Action entry for both transports.

### Task 5: Add the teaching Server and end-to-end proof

**Files:**
- Create: `examples/good_http_server.py`
- Modify: `tests/test_end_to_end.py`
- Modify: `.github/workflows/mcp-ci.yml`

**Steps:**

1. Implement a localhost-only, zero-dependency Streamable HTTP Server with Origin validation, secure sessions, version checks, correct notification handling and safe read-only discovery.
2. Launch it on an ephemeral port in an end-to-end test and run the real CLI subprocess against it.
3. Assert exit `0`, transport observations, and absence of raw session IDs.
4. Add a workflow step that starts the example Server and checks it through the composite Action.

### Task 6: Documentation and regression

**Files:**
- Modify: `README.md`
- Modify: `pyproject.toml`
- Modify: `src/mcp_ci/__init__.py`

**Steps:**

1. Document the HTTP command, exact safe probe sequence, eight rules, URL policy and limitations.
2. Bump the teaching demo to `0.3.0`.
3. Run `PYTHONPATH=src python3.12 -m unittest discover -s tests -v`.
4. Run stdio good/bad checks, HTTP good check, SARIF generation and compile checks.
5. Leave the repository uncommitted unless the user explicitly asks for a commit.
