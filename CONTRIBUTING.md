# Contributing to MCP CI

## Development setup

MCP CI requires Python 3.11+ and has no runtime dependencies.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m mcp_ci check --stdio "python3 examples/good_server.py"
```

## Rule contract

Every new rule must include:

- a stable, documented rule ID;
- deterministic evidence that excludes secrets, session IDs, cursors, and Resource contents;
- severity, a concrete message, and remediation;
- a passing fixture and at least one failing test;
- registration in `KNOWN_RULE_IDS`, so configuration cannot reference unknown rules.

Do not add model-based classification to the deterministic rule engine. Heuristics must be clearly described as review signals rather than proof of a vulnerability.

## Safety boundary

Contributions must not make the default probe call `tools/call`, `resources/read`, or `prompts/get`. A future active-testing mode would require a separate opt-in interface, explicit side-effect policy, sandboxing, and a distinct threat model.

Network tests must bind only to loopback. Test fixtures must not use real credentials or contact third-party services.

## Compatibility and changes

- Additive report fields and rule IDs are minor-compatible.
- Removing or changing rule semantics, config fields, exit codes, or baseline schema requires a major release.
- Baseline schema changes require a new `schema_version`; do not silently reinterpret old files.
- Keep the runtime standard-library-only unless a dependency has a clear security and maintenance justification.

Before proposing a change, run Python 3.11 and 3.12 tests and include the exact command/output summary.
