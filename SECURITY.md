# Security Policy

## Supported version

Security fixes are accepted for the latest major release. The current supported line is 1.x.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, execute a Tool, bypass transport authorization, or leak sensitive MCP metadata. Use the repository host's private security advisory channel. If no private channel exists, contact the maintainer privately before publishing details.

Include the affected version, transport, minimal reproduction, impact, and whether the reproduction performs any side effect. Use synthetic credentials and local fixtures only.

## Product security boundary

MCP CI performs metadata discovery and protocol checks. It does not:

- authenticate on behalf of an MCP deployment;
- prove that Tool annotations match implementation behavior;
- execute Tools, read Resources, or resolve Prompts;
- classify arbitrary content with an LLM;
- replace server-side authorization, sandboxing, egress control, or audit logging.

Baseline files intentionally hash Resource identities and metadata bodies, but Tool and Prompt dispatch names remain visible for review. Treat all reports, policy files, and baselines as repository security artifacts and review changes to them like code.
