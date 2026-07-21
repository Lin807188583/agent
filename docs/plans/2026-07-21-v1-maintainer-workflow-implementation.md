# MCP CI v1 Maintainer Workflow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete a release-ready maintainer workflow with project policy invariants, sanitized baselines, broader metadata conformance, and CI packaging.

**Architecture:** Extend strict local configuration without changing transports. Evaluate built-in rules from `ProbeEvidence`, append repository-policy and baseline findings, then apply audited rule controls and suppressions before rendering. Persist only canonical hashes and safe identifiers in baselines.

**Tech Stack:** Python 3.11+ standard library, asyncio, JSON, SHA-256, `fnmatch`, `unittest`, composite GitHub Actions.

---

### Task 1: Lock the v1 contracts with failing tests

**Files:**
- Modify: `tests/test_config.py`
- Create: `tests/test_baseline.py`
- Modify: `tests/test_rules.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_action_entry.py`

**Steps:**
1. Add strict-config tests for policy and rule controls.
2. Add deterministic/redacted baseline serialization and drift tests.
3. Add Resource, Resource Template, Prompt, and JSON-RPC contract tests.
4. Add CLI tests for mutually exclusive baseline read/write options.
5. Run targeted tests and confirm they fail for missing v1 APIs.

### Task 2: Implement policy invariants and rule controls

**Files:**
- Modify: `src/mcp_ci/config.py`
- Modify: `src/mcp_ci/rules.py`
- Modify: `src/mcp_ci/cli.py`

**Steps:**
1. Parse immutable `RuleControls` and `Policy` models with strict fields.
2. Produce `POL001`–`POL006` findings from evidence.
3. Apply severity overrides and audited disabled-rule filtering.
4. Apply suppressions last so policy findings can also be explicitly accepted.
5. Run config, rules, reporter, and CLI tests.

### Task 3: Implement sanitized baselines

**Files:**
- Create: `src/mcp_ci/baseline.py`
- Modify: `src/mcp_ci/cli.py`
- Modify: `src/mcp_ci/rules.py`
- Create: `examples/mcp-ci-baseline.json`

**Steps:**
1. Canonicalize capability and list metadata into safe identities and SHA-256 fingerprints.
2. Strictly load schema version 1 and reject unknown/malformed structures.
3. Compare snapshots and emit `BASE001`–`BASE005` without exposing raw URI/cursor/session values.
4. Add `--baseline` and `--write-baseline`, with atomic UTF-8 writes.
5. Run baseline and CLI tests.

### Task 4: Expand protocol and metadata conformance

**Files:**
- Modify: `src/mcp_ci/rules.py`
- Modify: `tests/test_rules.py`
- Modify: `examples/bad_server.py`

**Steps:**
1. Validate sampled JSON-RPC envelopes as `RPC001`–`RPC003`.
2. Validate Resource entries as `RES001`–`RES003`.
3. Validate Resource Templates as `RESTPL001`–`RESTPL002`.
4. Validate Prompt entries as `PROMPT001`–`PROMPT004`.
5. Keep all checks metadata-only and run rule/end-to-end tests.

### Task 5: Complete Action and release documentation

**Files:**
- Modify: `action.yml`
- Modify: `scripts/action_entry.py`
- Modify: `.github/workflows/mcp-ci.yml`
- Modify: `README.md`
- Modify: `pyproject.toml`
- Modify: `src/mcp_ci/__init__.py`
- Create: `CHANGELOG.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `examples/mcp-ci-policy.json`

**Steps:**
1. Add Action baseline input and document native GitHub protocol matrices.
2. Publish the strict policy and baseline workflows with safe review guidance.
3. Bump to `1.0.0` and document the compatibility/support boundary.
4. Run Python 3.11 and 3.12 full suites, CLI formats, baseline round-trip, and Action entry smoke tests.

No commit, tag, push, or external publication is performed without explicit user authorization.
