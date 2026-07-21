# Changelog

All notable changes are documented here. The project follows semantic versioning for CLI behavior, baseline schemas, configuration fields, and stable rule IDs.

## 1.0.0 - 2026-07-21

- Added strict repository policy invariants (`POL001`–`POL006`).
- Added sanitized, schema-versioned metadata baselines and drift findings (`BASE001`–`BASE005`).
- Added JSON-RPC response checks (`RPC001`–`RPC003`).
- Added Resource, Resource Template, and Prompt metadata rules.
- Added audited rule disabling and severity overrides.
- Added baseline support to the composite GitHub Action.
- Added Python 3.11/3.12 CI coverage, policy/baseline examples, and contributor/security documentation.

## 0.4.0 - 2026-07-21

- Added capability-gated Tools, Resources, Resource Templates, and Prompts discovery.
- Added bounded opaque-cursor pagination and `CAP`/`PAGE` rule families.
- Preserved the no-read/no-get/no-call safety boundary.

## 0.3.0 - 2026-07-21

- Added Streamable HTTP black-box checks, JSON/SSE parsing, Origin validation, protocol headers, and sanitized session evidence.

## 0.2.0 - 2026-07-21

- Added JUnit and SARIF reporters, strict suppression configuration, and reusable composite Action inputs.

## 0.1.0 - 2026-07-20

- Added the zero-dependency stdio transport, safe lifecycle probe, deterministic Tool/schema rules, text/JSON reports, and teaching fixtures.
