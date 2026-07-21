# MCP CI v1.1 Runtime Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bound complete probe runtime and retained diagnostics, write artifacts atomically, and verify installed wheels in CI.

**Architecture:** Keep transport-specific limits in the stdio client, carry sanitized diagnostic summaries through `ProbeEvidence`, and enforce the whole-run deadline at the CLI orchestration boundary. Share atomic filesystem behavior between baseline and report writers. Extend the existing dependency-free unittest and GitHub Actions matrix.

**Tech Stack:** Python 3.11+ standard library, asyncio, unittest, setuptools wheel builds, GitHub composite Actions.

---

### Task 1: Specify total probe timeout

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `tests/test_action_entry.py`
- Modify: `src/mcp_ci/cli.py`
- Modify: `scripts/action_entry.py`
- Modify: `action.yml`

**Steps:**
1. Add failing CLI tests for non-positive/non-finite values and an async probe that exceeds a tiny total budget.
2. Add a failing Action argument-mapping test for `MCP_CI_TOTAL_TIMEOUT`.
3. Run the two focused test modules and confirm the new assertions fail.
4. Add `--total-timeout`, finite-value validation, an asyncio deadline, and an audited limits observation.
5. Expose the Action input and pass it through the environment-backed argv builder.
6. Re-run focused tests and confirm they pass.

### Task 2: Bound stdio diagnostic evidence

**Files:**
- Modify: `tests/fixtures/rpc_fixture.py`
- Modify: `tests/test_transport.py`
- Modify: `tests/test_probe.py`
- Modify: `src/mcp_ci/transport.py`
- Modify: `src/mcp_ci/probe.py`
- Modify: `src/mcp_ci/rules.py`

**Steps:**
1. Extend the fixture with a deterministic diagnostic flood and add failing retention/count tests.
2. Add configurable internal count/text limits, bounded record helpers, and sanitized unsolicited-message summaries.
3. Carry actual totals and truncation flags into `ProbeEvidence` and report observations.
4. Confirm `MCP002` still fires using retained samples and existing short diagnostics remain readable.
5. Run transport, probe, and rule tests.

### Task 3: Share an atomic artifact writer

**Files:**
- Create: `src/mcp_ci/files.py`
- Create: `tests/test_files.py`
- Modify: `src/mcp_ci/baseline.py`
- Modify: `src/mcp_ci/cli.py`

**Steps:**
1. Add failing tests for successful replacement and failed replacement preserving the previous destination with no temporary-file leak.
2. Implement the standard-library atomic UTF-8 writer with flush, fsync, replace, and cleanup.
3. Refactor baseline persistence and CLI report output to use it.
4. Run file, baseline, and CLI tests.

### Task 4: Harden release CI and documentation

**Files:**
- Modify: `.github/workflows/mcp-ci.yml`
- Modify: `pyproject.toml`
- Modify: `src/mcp_ci/__init__.py`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/CONFIGURATION.md`

**Steps:**
1. Expand the Python matrix to 3.11–3.14 and add an explicit job timeout.
2. Add compile, wheel build, installation, installed CLI, and Action smoke gates.
3. Bump the project version to 1.1.0 and document timeout/diagnostic/artifact semantics.
4. Run version/rule-catalog consistency checks.

### Task 5: Full release verification

**Files:**
- Verify all project files; do not add generated artifacts.

**Steps:**
1. Run `compileall` and the complete unittest suite on Python 3.12 and the current Python.
2. Build and install the wheel in a temporary target, then run policy/baseline and Action entry smokes.
3. Run secret-pattern, forbidden-method, ignored-artifact, and `git diff --check` gates.
4. Review the final diff and report results. Do not push without explicit user authorization.
