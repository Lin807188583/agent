# MCP CI Demo Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a zero-dependency Python CLI that black-box checks a local stdio MCP server for basic protocol conformance and deterministic security invariants.

**Architecture:** Launch a user-supplied command as a subprocess, correlate line-delimited JSON-RPC responses by request ID, run a safe MCP lifecycle/discovery probe, then evaluate normalized evidence with pure rule functions. Report stable findings as text or JSON and convert severity into a CI exit code.

**Tech Stack:** Python 3.11+ standard library, `unittest`, `asyncio`, JSON-RPC 2.0, MCP `2025-11-25` request shape.

---

### Task 1: Project skeleton and finding model

**Files:**
- Create: `pyproject.toml`
- Create: `src/mcp_ci/__init__.py`
- Create: `src/mcp_ci/models.py`
- Test: `tests/test_models.py`

**Steps:**
1. Write tests for severity ordering, finding serialization, and threshold exit policy.
2. Run `python -m unittest tests.test_models -v`; expect failure because modules do not exist.
3. Implement `Severity`, `Finding`, `CheckReport`, and threshold helpers.
4. Re-run the test; expect pass.

### Task 2: Async stdio JSON-RPC transport

**Files:**
- Create: `src/mcp_ci/transport.py`
- Test: `tests/test_transport.py`

**Steps:**
1. Write integration tests using a tiny fixture process that returns responses out of order, emits stderr, and reports unknown methods.
2. Verify tests fail.
3. Implement subprocess lifecycle, one-reader response correlation, timeout handling, notification sending, stderr capture, and clean shutdown.
4. Verify requests are correlated by ID rather than arrival order.

### Task 3: MCP probe and evidence normalization

**Files:**
- Create: `src/mcp_ci/probe.py`
- Test: `tests/test_probe.py`

**Steps:**
1. Write tests that require `initialize`, `notifications/initialized`, `ping`, two `tools/list` calls, and an unknown-method probe.
2. Verify tests fail.
3. Implement the safe probe without calling any discovered tool.
4. Preserve negotiated version, server info, capabilities, tool snapshots, stderr, and protocol observations in `ProbeEvidence`.

### Task 4: Deterministic rule engine

**Files:**
- Create: `src/mcp_ci/rules.py`
- Test: `tests/test_rules.py`

**Steps:**
1. Write one failing test per stable rule ID.
2. Implement rules for version mismatch, malformed tool lists, duplicate/invalid names, missing descriptions, suspicious description instructions, schema structural errors, unknown required properties, secret-like defaults, destructive-name review, and manifest drift.
3. Ensure every finding includes severity, evidence, and remediation.
4. Verify rule tests pass without launching subprocesses.

### Task 5: CLI and reporters

**Files:**
- Create: `src/mcp_ci/cli.py`
- Create: `src/mcp_ci/__main__.py`
- Test: `tests/test_cli.py`

**Steps:**
1. Write tests for `--help`, text output, JSON output, invalid commands, timeout, and `--fail-on` behavior.
2. Implement `check --stdio`, `--format text|json`, `--timeout`, `--protocol-version`, and `--fail-on`.
3. Ensure operational failures use exit `2`; findings at threshold use exit `1`; clean checks use exit `0`.
4. Verify CLI tests pass.

### Task 6: Learning fixtures and CI example

**Files:**
- Create: `examples/good_server.py`
- Create: `examples/bad_server.py`
- Create: `.github/workflows/mcp-ci.yml`
- Create: `README.md`
- Create: `.gitignore`
- Test: `tests/test_end_to_end.py`

**Steps:**
1. Write end-to-end tests asserting the good fixture exits `0` and the bad fixture exposes expected rule IDs.
2. Implement both fixtures.
3. Document architecture, rule catalog, commands, output interpretation, safety boundary, and extension exercises.
4. Add a workflow that runs unit tests and checks the good fixture.
5. Run `python -m unittest discover -s tests -v`; expect all pass.
6. Run the good and bad fixture commands manually and save actual output for delivery.
