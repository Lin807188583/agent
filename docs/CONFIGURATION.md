# MCP CI Configuration

MCP CI reads one strict UTF-8 JSON file through `--config`. Unknown fields and ambiguous values fail with operational exit code `2` before the target starts.

## Complete shape

```json
{
  "rules": {
    "disabled": ["SCHEMA005"],
    "severity": {
      "TOOL004": "medium"
    }
  },
  "policy": {
    "allowed_protocol_versions": ["2025-11-25"],
    "required_capabilities": ["tools", "resources"],
    "required_tools": ["health/read"],
    "forbidden_tools": ["admin/*", "*/shell"],
    "max_tools": 50,
    "require_read_only": ["read_*", "*/read"]
  },
  "suppressions": [
    {
      "rule_id": "SCHEMA005",
      "tool": "legacy/read",
      "reason": "Migration tracked in issue #123",
      "expires": "2026-10-01"
    }
  ]
}
```

All sections are optional. Arrays reject empty strings and duplicates. `max_tools` is a non-negative integer. Tool patterns use Python-style, case-sensitive shell matching: `*`, `?`, and character classes are supported.

## Processing order

```text
built-in findings
  -> repository policy findings
  -> baseline drift findings
  -> disabled-rule filtering
  -> severity overrides
  -> scoped or global suppressions
  -> fail-on threshold
```

This order lets one repository control every stable rule family while keeping the controls visible in report observations.

## Rule controls

`rules.disabled` removes matching findings from the final finding list. The report records disabled IDs and the number of affected findings. Prefer a short-lived suppression when a finding is an accepted exception; disable a rule only when its semantics do not apply to the repository.

`rules.severity` accepts `info`, `low`, `medium`, `high`, or `critical`. A rule cannot be disabled and severity-overridden at the same time.

## Policy semantics

- Required capabilities and Tools use exact, case-sensitive names.
- Forbidden/read-only Tool selectors use case-sensitive globs.
- `readOnlyHint=true` is required by `require_read_only`; missing or false both fail.
- Policy cannot prove the underlying implementation is read-only. Authorization and side-effect controls remain server responsibilities.

## Suppressions

Suppressions keep findings in JSON/text/JUnit/SARIF but remove them from threshold failure calculation. A suppression requires a non-empty reason. `expires` is inclusive on that date and stops applying the following day. Tool-scoped suppressions win over rule-wide suppressions.

Configuration and baseline files should be owned and reviewed like security-sensitive code. Avoid allowing untrusted pull requests to rewrite them without approval.

## Runtime limits

Runtime limits are CLI and Action inputs rather than JSON policy fields. `--timeout` limits one protocol request and defaults to 5 seconds. `--total-timeout` limits the complete probe and defaults to 60 seconds. Both reject zero, negative, NaN, and infinite values before the target starts.

The report records both values in `observations.limits`. A complete-budget timeout is an operational failure with exit code `2`; it is not a suppressible security finding because the checker did not finish collecting evidence.

stdio diagnostics are retained within fixed internal count and text limits. `observations.diagnostics` distinguishes total and retained values and records truncation. Unsolicited JSON-RPC content is summarized instead of copied into artifacts.
