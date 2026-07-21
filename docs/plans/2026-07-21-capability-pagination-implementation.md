# MCP Capability and Pagination Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add safe capability-gated list discovery and opaque-cursor pagination validation to the MCP CI demo.

**Architecture:** Keep transport clients unchanged and extend the transport-neutral probe with a bounded list-flow helper. Store raw JSON-RPC responses only in `ProbeEvidence`; derive sanitized pagination/capability observations for reports. Rules validate capability shapes, list result shapes, cursor behavior, and the existing tool contract.

**Tech Stack:** Python 3.11+, asyncio, standard library HTTP/stdio transports, `unittest`, JSON reports.

---

### Task 1: Add failing model/probe tests

**Files:**
- Modify: `tests/test_probe.py`
- Modify: `tests/test_rules.py`

**Step 1: Write tests** for a fixture that declares tools, resources, and prompts, returns two pages for each list, and asserts the probe sends only list methods, forwards the exact cursor, and records page summaries without cursor values.

**Step 2: Run targeted tests** with `PYTHONPATH=src python3 -m unittest tests.test_probe tests.test_rules -v`; expect failures because the evidence fields and list flows do not exist.

### Task 2: Extend evidence and implement bounded list flows

**Files:**
- Modify: `src/mcp_ci/probe.py`

**Step 1:** Add typed response/page fields and capability/pagination observation fields while preserving `first_tools_response` and `second_tools_response` compatibility.

**Step 2:** Implement a helper that requests a list method, checks only local response metadata, sends the raw server cursor, stops at 20 pages, and detects repeated cursors without interpreting them.

**Step 3:** Gate flows on initialize capabilities, run tools/resources/templates/prompts list methods, and leave read/get/call methods untouched.

**Step 4:** Run probe tests; expect PASS.

### Task 3: Add deterministic capability and pagination rules

**Files:**
- Modify: `src/mcp_ci/rules.py`

**Step 1:** Add `CAP001`–`CAP004` and `PAGE001`–`PAGE005` to `KNOWN_RULE_IDS`.

**Step 2:** Validate capability object/listChanged types and each flow's list result, item-array, item-object, cursor type, duplicate cursor, and max-page observations.

**Step 3:** Make tool contract evaluation consume the complete paginated tool snapshot and compare first/final snapshots for `SUPPLY001`.

**Step 4:** Run rule tests and suppression/report tests; expect PASS.

### Task 4: Expand fixtures and integration coverage

**Files:**
- Modify: `tests/fixtures/mcp_fixture.py`
- Modify: `tests/fixtures/http_fixture.py`
- Modify: `tests/test_end_to_end.py`

**Step 1:** Add good paginated capability responses and opt-in malformed modes for repeated and non-string cursors.

**Step 2:** Assert stdio and HTTP probes discover all declared list surfaces, never issue `tools/call`, `resources/read`, or `prompts/get`, and report stable rule IDs for malformed servers.

**Step 3:** Run the full unittest suite.

### Task 5: Update product docs and version

**Files:**
- Modify: `README.md`
- Modify: `pyproject.toml`
- Modify: `.github/workflows/mcp-ci.yml`
- Modify: `examples/good_http_server.py`

**Step 1:** Document v0.4 safe methods, pagination limits, rule IDs, and the deliberate no-read/no-call boundary.

**Step 2:** Bump version to `0.4.0` and keep the GitHub Action inputs backward compatible.

**Step 3:** Run the complete suite plus CLI smoke checks for stdio, HTTP, JSON, SARIF, and Action entrypoint.

No commit or push is performed in this session; the working tree remains available for review.
