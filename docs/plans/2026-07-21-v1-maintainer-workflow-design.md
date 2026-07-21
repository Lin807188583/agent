# MCP CI v1 Maintainer Workflow Design

## Product outcome

v1 turns the teaching checker into a small but complete maintainer product: a CLI and GitHub Action that can prove protocol compatibility, enforce repository-specific security invariants, and detect unreviewed public-surface drift without executing Tools or reading Resources.

The release boundary remains deliberately narrow. It does not become an Agent gateway, OAuth scanner, model-based classifier, dashboard, sandbox, or tool executor. Those require different authority and threat models.

## Maintainer workflow

```text
MCP server / gateway
  -> safe black-box discovery
  -> built-in protocol and metadata rules
  -> repository policy invariants
  -> optional reviewed metadata baseline
  -> rule controls and expiring suppressions
  -> text / JSON / JUnit / SARIF
  -> deterministic CI exit code
```

The supported workflow is:

1. Run `mcp-ci check` locally against stdio or Streamable HTTP.
2. Declare project invariants in a strict JSON policy file.
3. Generate a sanitized baseline after review.
4. Check both built-in findings and baseline drift in pull requests.
5. Export SARIF/JUnit and fail at a configured severity threshold.

## Policy contract

The existing config grows two audited sections:

```json
{
  "rules": {
    "disabled": ["SCHEMA005"],
    "severity": {"TOOL004": "medium"}
  },
  "policy": {
    "allowed_protocol_versions": ["2025-11-25"],
    "required_capabilities": ["tools"],
    "required_tools": ["health/read"],
    "forbidden_tools": ["admin/*", "*/shell"],
    "max_tools": 50,
    "require_read_only": ["read_*", "*/read"]
  },
  "suppressions": []
}
```

Patterns use case-sensitive shell-style matching. Unknown fields or rule IDs, invalid severities, empty/duplicate values, and negative limits are operational errors. Rule disabling and severity changes remain visible under report observations.

Policy findings use stable IDs:

- `POL001`: negotiated protocol is outside the allowed set;
- `POL002`: required capability is missing;
- `POL003`: required Tool is missing;
- `POL004`: forbidden Tool is exposed;
- `POL005`: Tool count exceeds the configured maximum;
- `POL006`: a matched Tool is not explicitly `readOnlyHint=true`.

## Sanitized baseline

`--write-baseline PATH` writes a deterministic schema-versioned JSON snapshot. `--baseline PATH` compares a checked target with a reviewed snapshot.

The baseline contains negotiated protocol version, capability names, counts, public dispatch identifiers where safe, and SHA-256 fingerprints of canonical metadata. It never stores session IDs, pagination cursors, Resource contents, Prompt results, Tool results, or raw Resource URIs. Resource identities are hashed before persistence.

Baseline findings:

- `BASE001`: baseline schema or target protocol is incompatible;
- `BASE002`: capability set changed;
- `BASE003`: Tool public manifest changed;
- `BASE004`: Resource or Resource Template manifest changed;
- `BASE005`: Prompt manifest changed.

Baseline writing is an explicit local mutation and is mutually exclusive with baseline checking. A baseline is evidence for review, not an automatic assertion that the discovered surface is safe.

## Expanded metadata conformance

v1 validates every safely discovered list entry:

- JSON-RPC response envelopes and error objects;
- Resource URI/name/MIME shape and duplicate URIs;
- Resource Template URI-template/name/MIME shape;
- Prompt names, duplicate names, argument objects, required flags, and suspicious instruction-like descriptions.

The checker still does not dereference a URI, expand a URI template, resolve a Prompt, or execute a Tool.

## Release quality

The repository must include a changelog, contribution guide, security policy, versioned baseline/policy examples, a compatibility-matrix workflow example, and Python 3.11/3.12 tests. The composite Action stays zero-dependency and passes user input through environment variables rather than shell interpolation.
