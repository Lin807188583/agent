# MCP CI v0.2 Implementation Plan

## 1. Model the policy state

- Add a suppression value object with rule ID, optional tool scope, reason and optional expiration.
- Let a finding expose `active` or `suppressed` status without changing rule evaluation.
- Make `CheckReport.should_fail()` and active severity counts ignore suppressed findings.
- Keep suppressed findings fully serializable for audit.

## 2. Parse a strict configuration

- Add `mcp_ci.config` using `json` and `datetime` from the standard library.
- Validate the top-level object and supported fields.
- Reject unknown rule IDs, blank reasons, bad dates and duplicate scopes.
- Match tool-specific suppressions before rule-wide suppressions.
- Record declared, applied and expired suppression counts in observations.

## 3. Add CI-native reporters

- Add deterministic JUnit XML with suite properties, failures and skipped suppressions.
- Add SARIF 2.1.0 with rule descriptors, severity mapping, results and accepted suppressions.
- Test both formats by parsing the generated output instead of snapshotting whitespace.

## 4. Extend the CLI and Action

- Add `junit` and `sarif` format choices.
- Add optional `--config` and `--output` flags.
- Validate configuration before starting the MCP child process.
- Write report files as UTF-8 and convert filesystem failures into exit `2`.
- Pass optional Action inputs through environment variables into argv.

## 5. Document and verify

- Update README examples, architecture, output formats, suppression contract and roadmap.
- Update the sample workflow to generate a SARIF artifact.
- Run all unit and end-to-end tests under Python 3.12.
- Manually verify good, bad, suppressed, expired and output-file command paths.
