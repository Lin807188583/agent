# MCP CI v1.1 Runtime Hardening Design

## Goal

Make MCP CI predictable when a target is slow, noisy, or interrupted, and prove that the distributable package—not only the source checkout—works in CI. The release remains a zero-runtime-dependency, passive metadata checker.

## Product boundary

v1.1 does not add active Tool calls, Resource reads, Prompt resolution, OAuth credentials, pluggable rules, or gateway behavior. The configuration and baseline schemas remain version 1, and all 59 stable rule IDs keep their existing meaning. This is a reliability and release-engineering increment, not a new scanning surface.

## Runtime budgets

`--timeout` remains the per-request limit. A new `--total-timeout` option limits the complete probe, including initialization, both Tool snapshots, all capability-gated pagination, transport checks, and cleanup. Its default is 60 seconds and it must be finite and greater than zero. Exhausting it produces an operational error and exit code 2. Reports record both configured limits so a CI result is auditable.

The composite Action exposes the same input without interpolating it into shell source. Environment variables continue to be translated to an argv list by `scripts/action_entry.py`.

## Bounded stdio diagnostics

The stdio transport retains only a fixed number of protocol-noise lines, stderr lines, and unsolicited JSON-RPC messages. Text samples also have a fixed character limit. Separate total counters and truncation flags preserve auditability when retained samples are incomplete. Unsolicited messages retain only routing/shape metadata rather than arbitrary `params`, `result`, or `error` bodies.

Short existing diagnostics remain unchanged, so current rules and teaching fixtures keep their behavior. The final report exposes counts, retained counts, truncation state, and whether unsolicited content was summarized.

## Atomic artifact writes

Report and baseline files share one standard-library atomic text writer. It creates the parent directory, writes and fsyncs a temporary file in that directory, and replaces the destination only after the complete UTF-8 payload is durable. On failure, the previous destination remains intact and the temporary file is removed. Baseline validation still happens before any write.

## Release verification

GitHub Actions tests Python 3.11 through 3.14. Each matrix entry compiles sources, runs the full suite, builds a wheel, installs it, and executes an installed CLI smoke check before running the repository Action. Jobs have an explicit time limit. This catches missing package files, entry-point mistakes, unsupported syntax, and source-tree-only imports.

## Success criteria

- A deliberately slow probe stops with exit code 2 and a useful total-budget error.
- Non-finite and non-positive timeout values fail before a target starts.
- Diagnostic floods do not grow retained evidence beyond configured limits.
- Interrupted writes do not replace an existing report or leave temporary files.
- Python 3.11, 3.12, 3.13, and 3.14 are declared and exercised in CI.
- All existing tests and the no-call/no-read/no-get invariants continue to pass.
