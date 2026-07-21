# MCP CI v0.2: CI Reports and Auditable Suppressions

## Product goal

Version 0.2 makes the existing black-box checker useful inside ordinary maintainer CI. It adds JUnit and SARIF artifacts, output-to-file support, and narrowly scoped risk acceptance without changing the product into an MCP gateway or executing discovered tools.

The design keeps three guarantees from v0.1:

- the probe is deterministic and uses only Python's standard library;
- discovered MCP tools are never invoked;
- exit codes continue to distinguish a policy failure (`1`) from an operational error (`2`).

## Command-line contract

```text
mcp-ci check --stdio COMMAND
  [--format text|json|junit|sarif]
  [--output PATH]
  [--config PATH]
  [--fail-on SEVERITY]
```

Without `--output`, the selected report is printed to stdout. With `--output`, the report is written as UTF-8 and normal console output stays quiet. Parent directories are created so a workflow can write directly into an artifact directory.

Configuration is loaded before the target process starts. Invalid JSON, an unknown rule ID, an invalid date, an empty reason, or an ambiguous duplicate suppression is an operational error and exits `2`.

## Suppression model

The v0.2 configuration intentionally supports only one concern:

```json
{
  "suppressions": [
    {
      "rule_id": "SCHEMA005",
      "tool": "legacy/read",
      "reason": "Legacy compatibility; tracked in issue #123",
      "expires": "2026-10-01"
    }
  ]
}
```

`rule_id` and `reason` are required. `tool` narrows a suppression to a finding whose evidence contains the exact same tool name. Omitting `tool` accepts that rule for the whole target. `expires` is optional and uses an ISO calendar date; the suppression remains valid on that date and stops applying the following day.

When both a global and tool-specific suppression match, the tool-specific entry wins. Duplicate entries with the same `(rule_id, tool)` are rejected rather than depending on file order.

An applied suppression never deletes a finding. The finding remains in text, JSON, JUnit and SARIF output with its reason, scope and expiration date. It is excluded only from severity-threshold exit evaluation. Expired entries remain unapplied and are counted in report observations so stale risk acceptance is visible.

## Report semantics

Text and JSON preserve the v0.1 evidence and remediation fields. Summaries distinguish total, active and suppressed findings; severity counts describe active findings because those determine the CI exit status.

JUnit emits one test case per finding. Active findings are failures and suppressed findings are skipped with the risk-acceptance reason. Suite properties carry the target, protocol versions, CI threshold and threshold result. A clean target produces an empty, successful suite.

SARIF uses version 2.1.0, stable MCP CI rule IDs and GitHub-compatible levels:

- `critical` and `high` → `error`;
- `medium` → `warning`;
- `low` and `info` → `note`.

Suppressed SARIF results use an accepted external suppression with the required justification. Because this is a black-box runtime probe, results do not invent source locations; target and evidence are stored as result properties.

## Non-goals

Version 0.2 does not add a policy language, baselines, inline source suppressions, remote configuration, waivers without reasons, automatic Tool execution, Streamable HTTP, OAuth tests, or a hosted dashboard. These would enlarge the trust model and should be justified by maintainer feedback.

## Success criteria

- Existing text/JSON checks and exit semantics still pass.
- A matching, unexpired suppression keeps the finding visible but removes it from exit evaluation.
- An expired suppression does not change the exit code.
- Malformed or unauditable configuration exits `2` before launching the target.
- JUnit parses as XML and reports active/suppressed counts correctly.
- SARIF parses as JSON and contains stable rule metadata, levels and suppression justifications.
- The composite GitHub Action exposes `format`, `output` and `config` without interpolating user values into shell code.
