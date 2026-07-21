"""Deterministic MCP protocol and security-review rules."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import CheckReport, Finding, Severity
from .probe import ProbeEvidence


PORTABLE_TOOL_NAME = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
SUSPICIOUS_DESCRIPTION = re.compile(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior)|"
    r"system\s+prompt|do\s+not\s+tell|send\s+(?:the\s+)?secrets?|exfiltrat",
    re.IGNORECASE,
)
DESTRUCTIVE_NAME = re.compile(
    r"(?:^|[^a-z])(?:delete|remove|drop|write|update|execute|exec|shell|pay|transfer|send)(?:$|[^a-z])",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(
    r"(?:^sk-[A-Za-z0-9_-]{8,}|(?:token|secret|password|api[_-]?key)\s*[:=]|"
    r"AKIA[0-9A-Z]{16})",
    re.IGNORECASE,
)

# Configuration validates against the public, stable IDs supported by this build.
# Keeping this explicit makes adding or removing a CI contract a reviewable change.
KNOWN_RULE_IDS = frozenset(
    {
        "MCP001",
        "MCP002",
        "MCP003",
        "MCP004",
        "MCP005",
        "MCP006",
        "MCP007",
        "TOOL001",
        "TOOL002",
        "TOOL003",
        "TOOL004",
        "TOOL005",
        "SCHEMA001",
        "SCHEMA002",
        "SCHEMA003",
        "SCHEMA004",
        "SCHEMA005",
        "SEC001",
        "SUPPLY001",
        "HTTP001",
        "HTTP002",
        "HTTP003",
        "HTTP004",
        "HTTP005",
        "HTTP006",
        "HTTP007",
        "HTTP008",
        "CAP001",
        "CAP002",
        "CAP003",
        "CAP004",
        "PAGE001",
        "PAGE002",
        "PAGE003",
        "PAGE004",
        "PAGE005",
        "POL001",
        "POL002",
        "POL003",
        "POL004",
        "POL005",
        "POL006",
        "BASE001",
        "BASE002",
        "BASE003",
        "BASE004",
        "BASE005",
        "RPC001",
        "RPC002",
        "RPC003",
        "RES001",
        "RES002",
        "RES003",
        "RESTPL001",
        "RESTPL002",
        "PROMPT001",
        "PROMPT002",
        "PROMPT003",
        "PROMPT004",
    }
)


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    *,
    evidence: dict[str, Any] | None = None,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        evidence=evidence or {},
        remediation=remediation,
    )


def _tools_shape(response: dict[str, Any]) -> tuple[bool, list[Any]]:
    result = response.get("result")
    if not isinstance(result, dict):
        return False, []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return False, []
    return True, tools


def _canonical_manifest(tools: list[dict[str, Any]]) -> str:
    ordered = sorted(tools, key=lambda tool: str(tool.get("name", "")))
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _walk_defaults(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            nested_path = f"{path}.{key}"
            if key == "default":
                yield nested_path, nested
            yield from _walk_defaults(nested, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_defaults(nested, f"{path}[{index}]")


_LIST_FLOWS = (
    ("tools", "tools_list_pages", "tools"),
    ("resources", "resources_list_pages", "resources"),
    ("resource_templates", "resource_templates_list_pages", "resourceTemplates"),
    ("prompts", "prompts_list_pages", "prompts"),
)

_LIST_METHODS = {
    "tools": "tools/list",
    "resources": "resources/list",
    "resource_templates": "resources/templates/list",
    "prompts": "prompts/list",
}


def _capability_findings(evidence: ProbeEvidence) -> list[Finding]:
    """Validate capability declarations and safe list/pagination evidence."""

    initialize_result = evidence.initialize_response.get("result")
    if not isinstance(initialize_result, dict):
        return []
    capabilities = initialize_result.get("capabilities")
    if not isinstance(capabilities, dict):
        return [
            _finding(
                "CAP002",
                "Capabilities must be an object",
                Severity.HIGH,
                "The initialize result capabilities field must be a JSON object.",
                evidence={"type": type(capabilities).__name__},
                remediation="Return capabilities as an object whose keys are supported MCP capability groups.",
            )
        ]

    findings: list[Finding] = []
    for flow_name, field_name, item_key in _LIST_FLOWS:
        if flow_name == "resource_templates":
            capability_name = "resources"
        else:
            capability_name = flow_name
        if capability_name not in capabilities:
            continue
        capability = capabilities[capability_name]
        if not isinstance(capability, dict):
            findings.append(
                _finding(
                    "CAP002",
                    "Capability declaration is not an object",
                    Severity.HIGH,
                    f"The {capability_name} capability must be an object.",
                    evidence={"capability": capability_name, "type": type(capability).__name__},
                    remediation="Use an object value for each declared capability, even when it has no options.",
                )
            )
            continue
        if "listChanged" in capability and not isinstance(capability["listChanged"], bool):
            findings.append(
                _finding(
                    "CAP003",
                    "listChanged capability flag is not boolean",
                    Severity.MEDIUM,
                    f"The {capability_name}.listChanged field must be a boolean when present.",
                    evidence={"capability": capability_name, "type": type(capability["listChanged"]).__name__},
                    remediation="Use true or false for listChanged and emit the corresponding notification when true.",
                )
            )

        pages = getattr(evidence, field_name)
        # Keep hand-built pre-pagination evidence compatible with v1 rules.
        # Real probes populate the paginated field; older callers may only
        # provide the legacy Tool response fields.
        if not pages and flow_name == "tools" and evidence.first_tools_response:
            pages = [evidence.first_tools_response]
        observation = evidence.pagination_observations.get(flow_name, {})
        termination = observation.get("termination") if isinstance(observation, dict) else None
        if termination is None and pages:
            last_result = pages[-1].get("result")
            termination = (
                "complete"
                if isinstance(last_result, dict) and "nextCursor" not in last_result
                else "invalid-result"
            )
        available = bool(pages) and termination in {"complete", "missing-next-cursor"}
        if not available:
            list_method = _LIST_METHODS[flow_name]
            findings.append(
                _finding(
                    "CAP001",
                    "Declared capability list method failed",
                    Severity.HIGH,
                    f"The {flow_name} capability was declared but {list_method} did not return a complete list.",
                    evidence={"capability": capability_name, "flow": flow_name, "termination": termination},
                    remediation=f"Implement {list_method} and return a paginated result with {item_key} as an array.",
                )
            )
            if "listChanged" in capability:
                findings.append(
                    _finding(
                        "CAP004",
                        "listChanged capability has no usable list method",
                        Severity.MEDIUM,
                        f"The {capability_name}.listChanged declaration cannot be verified because its base list method failed.",
                        evidence={"capability": capability_name, "flow": flow_name},
                        remediation="Make the base list method available before advertising listChanged notifications.",
                    )
                )

        for page in pages:
            result = page.get("result")
            if not isinstance(result, dict):
                continue
            items = result.get(item_key)
            if "nextCursor" in result and not isinstance(result["nextCursor"], str):
                findings.append(
                    _finding(
                        "PAGE001",
                        "Pagination cursor is not a string",
                        Severity.HIGH,
                        f"The {flow_name} list returned a non-string nextCursor.",
                        evidence={"flow": flow_name, "type": type(result["nextCursor"]).__name__},
                        remediation="Return nextCursor as an opaque string, or omit it when the list is complete.",
                    )
                )
            if not isinstance(items, list):
                findings.append(
                    _finding(
                        "PAGE005",
                        "Paginated list collection is not an array",
                        Severity.HIGH,
                        f"The {flow_name} list result must contain an array named {item_key}.",
                        evidence={"flow": flow_name, "item_key": item_key, "type": type(items).__name__},
                        remediation=f"Return {{\"{item_key}\": [...]}} for every successful {flow_name} list page.",
                    )
                )
                continue
            if any(not isinstance(item, dict) for item in items):
                findings.append(
                    _finding(
                        "PAGE004",
                        "Paginated list entries are not objects",
                        Severity.HIGH,
                        f"At least one {flow_name} list entry is not a JSON object.",
                        evidence={"flow": flow_name, "non_object_count": sum(not isinstance(item, dict) for item in items)},
                        remediation="Return one complete JSON object for every entry in a list page.",
                    )
                )

        if termination == "repeated-cursor":
            findings.append(
                _finding(
                    "PAGE002",
                    "Pagination cursor repeated",
                    Severity.HIGH,
                    f"The {flow_name} list returned a cursor already seen in the same flow.",
                    evidence={"flow": flow_name},
                    remediation="Treat cursors as opaque and advance to a fresh cursor or omit nextCursor at the final page.",
                )
            )
        elif termination == "max-pages":
            findings.append(
                _finding(
                    "PAGE003",
                    "Pagination exceeded the inspection limit",
                    Severity.HIGH,
                    f"The {flow_name} list still returned nextCursor after the bounded page limit.",
                    evidence={"flow": flow_name, "max_pages": 20},
                    remediation="Terminate pagination within the client contract or expose a finite list snapshot.",
                )
            )
    return findings


def _response_records(
    evidence: ProbeEvidence,
) -> list[tuple[str, dict[str, Any]]]:
    records = [
        ("initialize", evidence.initialize_response),
        ("ping", evidence.ping_response),
        ("unknown-method", evidence.unknown_method_response),
    ]
    flows = (
        ("tools/list", evidence.tools_list_pages),
        ("tools/list-second-snapshot", evidence.second_tools_list_pages),
        ("resources/list", evidence.resources_list_pages),
        ("resources/templates/list", evidence.resource_templates_list_pages),
        ("prompts/list", evidence.prompts_list_pages),
    )
    for operation, pages in flows:
        for index, page in enumerate(pages):
            records.append((f"{operation}[{index}]", page))
    return [(operation, response) for operation, response in records if response]


def _rpc_findings(evidence: ProbeEvidence) -> list[Finding]:
    findings: list[Finding] = []
    for operation, response in _response_records(evidence):
        if response.get("jsonrpc") != "2.0":
            findings.append(
                _finding(
                    "RPC001",
                    "JSON-RPC version marker is invalid",
                    Severity.HIGH,
                    f"The {operation} response must contain jsonrpc=\"2.0\".",
                    evidence={"operation": operation, "jsonrpc": response.get("jsonrpc")},
                    remediation="Return a JSON-RPC 2.0 response envelope for every request.",
                )
            )
        has_result = "result" in response
        has_error = "error" in response
        if "id" not in response or has_result == has_error:
            findings.append(
                _finding(
                    "RPC002",
                    "JSON-RPC response envelope is ambiguous",
                    Severity.HIGH,
                    f"The {operation} response must contain an id and exactly one of result or error.",
                    evidence={
                        "operation": operation,
                        "has_id": "id" in response,
                        "has_result": has_result,
                        "has_error": has_error,
                    },
                    remediation="Echo the request id and return either result or error, never both.",
                )
            )
        if has_error:
            error = response.get("error")
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else None
            if (
                not isinstance(error, dict)
                or isinstance(code, bool)
                or not isinstance(code, int)
                or not isinstance(message, str)
                or not message
            ):
                findings.append(
                    _finding(
                        "RPC003",
                        "JSON-RPC error object is malformed",
                        Severity.HIGH,
                        f"The {operation} error must contain an integer code and non-empty message.",
                        evidence={
                            "operation": operation,
                            "error_type": type(error).__name__,
                            "code_type": type(code).__name__,
                            "message_type": type(message).__name__,
                        },
                        remediation="Return a JSON-RPC error object with integer code and string message.",
                    )
                )
    return findings


def _absolute_uri(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return bool(urlsplit(value).scheme)
    except ValueError:
        return False


def _resource_findings(evidence: ProbeEvidence) -> list[Finding]:
    findings: list[Finding] = []
    raw_resources = ProbeEvidence._items_from_pages(
        evidence.resources_list_pages, "resources"
    )
    resources = [item for item in raw_resources if isinstance(item, dict)]
    uri_indexes: dict[str, list[int]] = {}
    for index, resource in enumerate(resources):
        uri = resource.get("uri")
        name = resource.get("name")
        if not _absolute_uri(uri) or not isinstance(name, str) or not name:
            findings.append(
                _finding(
                    "RES001",
                    "Resource required fields are malformed",
                    Severity.HIGH,
                    "Each Resource must have an absolute URI and a non-empty name.",
                    evidence={"index": index},
                    remediation="Return a stable absolute URI and non-empty name for every Resource.",
                )
            )
        if isinstance(uri, str):
            uri_indexes.setdefault(uri, []).append(index)
        invalid_optional = sorted(
            field
            for field in ("title", "description", "mimeType")
            if field in resource and not isinstance(resource[field], str)
        )
        size = resource.get("size")
        if "size" in resource and (
            isinstance(size, bool) or not isinstance(size, int) or size < 0
        ):
            invalid_optional.append("size")
        if invalid_optional:
            findings.append(
                _finding(
                    "RES003",
                    "Resource optional metadata has invalid types",
                    Severity.MEDIUM,
                    "Optional Resource metadata must use the protocol-defined scalar types.",
                    evidence={"index": index, "fields": invalid_optional},
                    remediation="Use strings for title/description/mimeType and a non-negative integer for size.",
                )
            )
    duplicates = [indexes for indexes in uri_indexes.values() if len(indexes) > 1]
    if duplicates:
        findings.append(
            _finding(
                "RES002",
                "Duplicate Resource URIs",
                Severity.HIGH,
                "Resource URIs are client-facing identifiers and must be unique in one snapshot.",
                evidence={"duplicate_index_groups": duplicates},
                remediation="Expose one unambiguous Resource entry per URI.",
            )
        )

    raw_templates = ProbeEvidence._items_from_pages(
        evidence.resource_templates_list_pages, "resourceTemplates"
    )
    templates = [item for item in raw_templates if isinstance(item, dict)]
    template_indexes: dict[str, list[int]] = {}
    for index, template in enumerate(templates):
        uri_template = template.get("uriTemplate")
        name = template.get("name")
        if (
            not isinstance(uri_template, str)
            or not uri_template
            or not isinstance(name, str)
            or not name
        ):
            findings.append(
                _finding(
                    "RESTPL001",
                    "Resource Template required fields are malformed",
                    Severity.HIGH,
                    "Each Resource Template must have a non-empty uriTemplate and name.",
                    evidence={"index": index},
                    remediation="Return a non-empty RFC 6570 URI template and stable display name.",
                )
            )
        if isinstance(uri_template, str):
            template_indexes.setdefault(uri_template, []).append(index)
        invalid_optional = sorted(
            field
            for field in ("title", "description", "mimeType")
            if field in template and not isinstance(template[field], str)
        )
        if invalid_optional:
            findings.append(
                _finding(
                    "RESTPL002",
                    "Resource Template metadata is ambiguous",
                    Severity.MEDIUM,
                    "Optional Resource Template metadata has invalid types.",
                    evidence={"index": index, "fields": invalid_optional},
                    remediation="Use string title, description, and mimeType values.",
                )
            )
    template_duplicates = [
        indexes for indexes in template_indexes.values() if len(indexes) > 1
    ]
    if template_duplicates:
        findings.append(
            _finding(
                "RESTPL002",
                "Duplicate Resource Templates",
                Severity.MEDIUM,
                "Resource URI templates must be unique in one snapshot.",
                evidence={"duplicate_index_groups": template_duplicates},
                remediation="Expose one unambiguous definition per URI template.",
            )
        )
    return findings


def _prompt_findings(evidence: ProbeEvidence) -> list[Finding]:
    findings: list[Finding] = []
    raw_prompts = ProbeEvidence._items_from_pages(
        evidence.prompts_list_pages, "prompts"
    )
    prompts = [item for item in raw_prompts if isinstance(item, dict)]
    names: list[str] = []
    for index, prompt in enumerate(prompts):
        name = prompt.get("name")
        label = name if isinstance(name, str) else f"prompt[{index}]"
        if isinstance(name, str):
            names.append(name)
        if not isinstance(name, str) or PORTABLE_TOOL_NAME.fullmatch(name) is None:
            findings.append(
                _finding(
                    "PROMPT001",
                    "Prompt name is missing or non-portable",
                    Severity.MEDIUM,
                    f"{label!r} is not a conservative cross-client Prompt identifier.",
                    evidence={"prompt": label},
                    remediation="Use a stable 1-128 character identifier with letters, digits, dot, slash, underscore, or hyphen.",
                )
            )
        description = prompt.get("description")
        if description is not None and not isinstance(description, str):
            findings.append(
                _finding(
                    "PROMPT003",
                    "Prompt metadata is malformed",
                    Severity.MEDIUM,
                    f"Prompt {label!r} has a non-string description.",
                    evidence={"prompt": label, "field": "description"},
                    remediation="Use a string description and treat it as untrusted metadata.",
                )
            )
        elif isinstance(description, str) and SUSPICIOUS_DESCRIPTION.search(description):
            findings.append(
                _finding(
                    "PROMPT004",
                    "Prompt description contains suspicious instruction-like text",
                    Severity.HIGH,
                    f"Prompt {label!r} contains language commonly used to override an Agent.",
                    evidence={"prompt": label, "description": description[:240]},
                    remediation="Remove policy-bypass instructions and review the Prompt server's provenance.",
                )
            )
        arguments = prompt.get("arguments", [])
        argument_errors: list[str] = []
        argument_names: list[str] = []
        if not isinstance(arguments, list):
            argument_errors.append("arguments-not-array")
        else:
            for argument_index, argument in enumerate(arguments):
                if not isinstance(argument, dict):
                    argument_errors.append(f"argument[{argument_index}]-not-object")
                    continue
                argument_name = argument.get("name")
                if not isinstance(argument_name, str) or not argument_name:
                    argument_errors.append(f"argument[{argument_index}]-invalid-name")
                else:
                    argument_names.append(argument_name)
                for field in ("title", "description"):
                    if field in argument and not isinstance(argument[field], str):
                        argument_errors.append(f"argument[{argument_index}]-invalid-{field}")
                if "required" in argument and not isinstance(argument["required"], bool):
                    argument_errors.append(f"argument[{argument_index}]-invalid-required")
            if len(argument_names) != len(set(argument_names)):
                argument_errors.append("duplicate-argument-names")
        if argument_errors:
            findings.append(
                _finding(
                    "PROMPT003",
                    "Prompt arguments are malformed",
                    Severity.HIGH,
                    f"Prompt {label!r} does not expose a portable argument contract.",
                    evidence={"prompt": label, "errors": argument_errors},
                    remediation="Return unique argument objects with string names and boolean required flags.",
                )
            )
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        findings.append(
            _finding(
                "PROMPT002",
                "Duplicate Prompt names",
                Severity.HIGH,
                "Prompt names are dispatch identifiers and must be unique in one snapshot.",
                evidence={"prompts": duplicates},
                remediation="Give every Prompt a stable unique name.",
            )
        )
    return findings


def _evaluate_http(evidence: ProbeEvidence) -> list[Finding]:
    if evidence.transport != "http":
        return []

    observations = evidence.transport_observations
    findings: list[Finding] = []
    if observations.get("origin_status") != 403:
        findings.append(
            _finding(
                "HTTP001",
                "Invalid Origin was not rejected",
                Severity.HIGH,
                "A Streamable HTTP endpoint must reject an invalid Origin with HTTP 403.",
                evidence={"status": observations.get("origin_status")},
                remediation="Validate Origin on every connection before processing MCP messages.",
            )
        )

    initialize_status = observations.get("initialize_status")
    if not isinstance(initialize_status, int) or not 200 <= initialize_status < 300:
        findings.append(
            _finding(
                "HTTP002",
                "Initialize POST did not return a successful HTTP status",
                Severity.HIGH,
                "The MCP endpoint did not accept the Streamable HTTP initialize request.",
                evidence={"status": initialize_status},
                remediation="Serve the MCP endpoint directly and accept initialize through HTTP POST without redirects.",
            )
        )

    allowed_types = {"application/json", "text/event-stream"}
    raw_entries = observations.get("response_content_types", [])
    entries = raw_entries if isinstance(raw_entries, list) else []
    invalid_content_types = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("status"), int)
        and 200 <= entry["status"] < 300
        and entry.get("content_type") not in allowed_types
    ]
    parse_error_count = observations.get("parse_error_count", 0)
    if invalid_content_types or (
        isinstance(parse_error_count, int) and parse_error_count > 0
    ):
        findings.append(
            _finding(
                "HTTP003",
                "HTTP response representation is not valid MCP",
                Severity.HIGH,
                "Successful JSON-RPC requests must return application/json or text/event-stream with parseable messages.",
                evidence={
                    "invalid_responses": invalid_content_types,
                    "parse_error_count": parse_error_count,
                },
                remediation="Return one UTF-8 JSON-RPC object as application/json or valid SSE data events.",
            )
        )

    initialized = isinstance(evidence.initialize_response.get("result"), dict)
    notification_status = observations.get("notification_status")
    notification_body_size = observations.get("notification_body_size")
    if initialized and (
        notification_status != 202 or notification_body_size != 0
    ):
        findings.append(
            _finding(
                "HTTP004",
                "Initialized notification did not return 202 with an empty body",
                Severity.MEDIUM,
                "An accepted JSON-RPC notification must use HTTP 202 Accepted and no response body.",
                evidence={
                    "status": notification_status,
                    "body_size": notification_body_size,
                },
                remediation="Acknowledge accepted notifications with HTTP 202 and Content-Length: 0.",
            )
        )

    if initialized:
        get_status = observations.get("get_status")
        get_content_type = observations.get("get_content_type")
        get_is_valid = get_status == 405 or (
            isinstance(get_status, int)
            and 200 <= get_status < 300
            and get_content_type == "text/event-stream"
        )
        if not get_is_valid:
            findings.append(
                _finding(
                    "HTTP005",
                    "GET listener contract is invalid",
                    Severity.MEDIUM,
                    "GET must either open a text/event-stream response or return HTTP 405.",
                    evidence={
                        "status": get_status,
                        "content_type": get_content_type,
                    },
                    remediation="Return SSE for server-initiated messages, or 405 when GET listening is unsupported.",
                )
            )

        invalid_protocol_status = observations.get("invalid_protocol_status")
        if invalid_protocol_status != 400:
            findings.append(
                _finding(
                    "HTTP006",
                    "Invalid protocol version was not rejected",
                    Severity.MEDIUM,
                    "An invalid MCP-Protocol-Version header must produce HTTP 400.",
                    evidence={"status": invalid_protocol_status},
                    remediation="Validate MCP-Protocol-Version before dispatching the JSON-RPC message.",
                )
            )

    session_issued = observations.get("session_id_issued") is True
    session_length = observations.get("session_id_length")
    visible_ascii = observations.get("session_id_visible_ascii")
    if session_issued and (session_length == 0 or visible_ascii is not True):
        findings.append(
            _finding(
                "HTTP007",
                "Session ID contains invalid characters",
                Severity.HIGH,
                "MCP-Session-Id must be non-empty and contain only visible ASCII characters.",
                evidence={
                    "length": session_length,
                    "visible_ascii": visible_ascii,
                },
                remediation="Generate a non-empty cryptographically secure session ID using visible ASCII only.",
            )
        )

    if session_issued and observations.get("missing_session_status") != 400:
        findings.append(
            _finding(
                "HTTP008",
                "Missing session header was not rejected",
                Severity.MEDIUM,
                "After issuing a session, the server should reject subsequent requests without it using HTTP 400.",
                evidence={"status": observations.get("missing_session_status")},
                remediation="Require MCP-Session-Id on every request after initialization and keep authorization independent of the session.",
            )
        )
    return findings


def evaluate(evidence: ProbeEvidence) -> list[Finding]:
    findings: list[Finding] = _evaluate_http(evidence)
    findings.extend(_rpc_findings(evidence))
    findings.extend(_capability_findings(evidence))
    findings.extend(_resource_findings(evidence))
    findings.extend(_prompt_findings(evidence))

    initialize_result = evidence.initialize_response.get("result")
    if not isinstance(initialize_result, dict):
        findings.append(
            _finding(
                "MCP001",
                "Initialization did not succeed",
                Severity.HIGH,
                "The server did not return an MCP initialize result.",
                evidence={"response": evidence.initialize_response},
                remediation="Return a valid initialize result before accepting normal requests.",
            )
        )

    if evidence.transport == "stdio" and evidence.protocol_noise:
        findings.append(
            _finding(
                "MCP002",
                "Non-protocol data was written to stdout",
                Severity.HIGH,
                "MCP stdio reserves stdout for JSON-RPC messages; debug output can corrupt framing.",
                evidence={"sample": evidence.protocol_noise[:3]},
                remediation="Write logs to stderr and keep stdout protocol-only.",
            )
        )

    if initialize_result and evidence.negotiated_protocol_version is None:
        findings.append(
            _finding(
                "MCP003",
                "Negotiated protocol version is missing",
                Severity.HIGH,
                "The initialize result did not contain a string protocolVersion.",
                remediation="Return the protocol version selected by the server.",
            )
        )
    elif (
        evidence.negotiated_protocol_version is not None
        and evidence.negotiated_protocol_version != evidence.requested_protocol_version
    ):
        findings.append(
            _finding(
                "MCP004",
                "Protocol version differs from the requested baseline",
                Severity.MEDIUM,
                "The server selected a different protocol version; CI expectations may not apply.",
                evidence={
                    "requested": evidence.requested_protocol_version,
                    "negotiated": evidence.negotiated_protocol_version,
                },
                remediation="Pin a supported version in CI and run the matching conformance profile.",
            )
        )

    if initialize_result and "result" not in evidence.ping_response:
        findings.append(
            _finding(
                "MCP005",
                "Ping did not succeed",
                Severity.MEDIUM,
                "The initialized server did not return a successful ping result.",
                evidence={"response": evidence.ping_response},
                remediation="Support the MCP ping utility after initialization.",
            )
        )

    unknown_error = evidence.unknown_method_response.get("error")
    unknown_code = unknown_error.get("code") if isinstance(unknown_error, dict) else None
    if initialize_result and unknown_code != -32601:
        findings.append(
            _finding(
                "MCP006",
                "Unknown methods do not use the JSON-RPC Method not found error",
                Severity.MEDIUM,
                "The server should reject an unknown request with error code -32601.",
                evidence={"response": evidence.unknown_method_response},
                remediation="Return JSON-RPC -32601 without executing fallback behavior.",
            )
        )

    supports_tools = isinstance(evidence.capabilities, dict) and "tools" in evidence.capabilities
    if not supports_tools:
        return findings

    valid_tools_shape, raw_tools = _tools_shape(evidence.first_tools_response)
    if not valid_tools_shape:
        findings.append(
            _finding(
                "MCP007",
                "tools/list result is malformed",
                Severity.HIGH,
                "The tools/list result must contain a tools array.",
                evidence={"response": evidence.first_tools_response},
                remediation="Return {\"tools\": [...]} from tools/list.",
            )
        )
        return findings

    if evidence.tools_list_pages:
        raw_tools = evidence.all_tools
    tools = [tool for tool in raw_tools if isinstance(tool, dict)]
    if len(tools) != len(raw_tools):
        findings.append(
            _finding(
                "TOOL001",
                "Tool entries must be JSON objects",
                Severity.HIGH,
                "At least one tools/list entry is not an object.",
                remediation="Return a complete tool definition object for every array item.",
            )
        )

    names = [tool.get("name") for tool in tools]
    string_names = [name for name in names if isinstance(name, str)]
    duplicates = sorted({name for name in string_names if string_names.count(name) > 1})
    if duplicates:
        findings.append(
            _finding(
                "TOOL002",
                "Duplicate tool names",
                Severity.HIGH,
                "Tool names are dispatch identifiers and must be unique within a server snapshot.",
                evidence={"names": duplicates},
                remediation="Give each tool a stable, unique name and reject collisions during registration.",
            )
        )

    for index, tool in enumerate(tools):
        name = tool.get("name")
        label = name if isinstance(name, str) else f"tool[{index}]"
        if not isinstance(name, str) or not PORTABLE_TOOL_NAME.fullmatch(name):
            findings.append(
                _finding(
                    "TOOL003",
                    "Tool name is missing or non-portable",
                    Severity.MEDIUM,
                    f"{label!r} is not a conservative cross-client tool identifier.",
                    evidence={"tool": label},
                    remediation="Use 1-128 ASCII letters, digits, dot, slash, underscore, or hyphen.",
                )
            )

        description = tool.get("description")
        if not isinstance(description, str) or not description.strip():
            findings.append(
                _finding(
                    "TOOL004",
                    "Tool description is missing",
                    Severity.LOW,
                    f"{label!r} does not explain its purpose and side effects.",
                    evidence={"tool": label},
                    remediation="Document purpose, important constraints, and side effects without instructions to bypass policy.",
                )
            )
        elif SUSPICIOUS_DESCRIPTION.search(description):
            findings.append(
                _finding(
                    "TOOL005",
                    "Tool description contains suspicious instruction-like text",
                    Severity.HIGH,
                    f"{label!r} contains language commonly used to steer or override an Agent.",
                    evidence={"tool": label, "description": description[:240]},
                    remediation="Treat descriptions as untrusted metadata; remove instruction injection and review server provenance.",
                )
            )

        schema = tool.get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            findings.append(
                _finding(
                    "SCHEMA001",
                    "inputSchema must be an object schema",
                    Severity.HIGH,
                    f"{label!r} does not expose a JSON Schema object contract.",
                    evidence={"tool": label},
                    remediation="Provide inputSchema with type=object and explicit properties.",
                )
            )
            continue

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            findings.append(
                _finding(
                    "SCHEMA002",
                    "Schema properties is not an object",
                    Severity.HIGH,
                    f"{label!r} has a malformed properties declaration.",
                    evidence={"tool": label},
                    remediation="Declare properties as a JSON object keyed by parameter name.",
                )
            )
            properties = {}

        required = schema.get("required", [])
        invalid_required = not isinstance(required, list)
        unknown_required = (
            sorted(item for item in required if isinstance(item, str) and item not in properties)
            if isinstance(required, list)
            else []
        )
        if invalid_required or unknown_required:
            findings.append(
                _finding(
                    "SCHEMA003",
                    "Required parameters are inconsistent with properties",
                    Severity.MEDIUM,
                    f"{label!r} has an invalid required declaration.",
                    evidence={"tool": label, "unknown_required": unknown_required},
                    remediation="Make required an array containing only declared property names.",
                )
            )

        for path, default in _walk_defaults(schema):
            if isinstance(default, str) and SECRET_VALUE.search(default):
                findings.append(
                    _finding(
                        "SCHEMA004",
                        "Schema contains a secret-like default",
                        Severity.HIGH,
                        f"{label!r} exposes a credential-shaped value in public tool metadata.",
                        evidence={"tool": label, "path": path},
                        remediation="Inject credentials at execution time; never publish them in tool schemas or model context.",
                    )
                )

        annotations = tool.get("annotations")
        has_read_only_hint = isinstance(annotations, dict) and "readOnlyHint" in annotations
        if isinstance(name, str) and DESTRUCTIVE_NAME.search(name) and not has_read_only_hint:
            findings.append(
                _finding(
                    "SEC001",
                    "Potentially mutating tool lacks an explicit read-only hint",
                    Severity.MEDIUM,
                    f"{label!r} appears mutating and should receive explicit human and policy review.",
                    evidence={"tool": label},
                    remediation="Declare accurate annotations, then enforce authorization independently because annotations are untrusted hints.",
                )
            )

        if schema.get("additionalProperties") is not False:
            findings.append(
                _finding(
                    "SCHEMA005",
                    "Tool schema accepts undeclared parameters",
                    Severity.LOW,
                    f"{label!r} does not explicitly reject additional properties.",
                    evidence={"tool": label},
                    remediation="Consider additionalProperties=false when undeclared arguments have no legitimate use.",
                )
            )

    second_shape, _ = _tools_shape(evidence.second_tools_response)
    if valid_tools_shape and second_shape:
        first_snapshot = (
            evidence.all_tools if evidence.tools_list_pages else evidence.first_tools
        )
        second_snapshot = (
            ProbeEvidence._items_from_pages(
                evidence.second_tools_list_pages, "tools"
            )
            if evidence.second_tools_list_pages
            else evidence.second_tools
        )
        first_objects = [item for item in first_snapshot if isinstance(item, dict)]
        second_objects = [item for item in second_snapshot if isinstance(item, dict)]
        if _canonical_manifest(first_objects) != _canonical_manifest(second_objects):
            findings.append(
                _finding(
                    "SUPPLY001",
                    "Tool manifest changed during one probe",
                    Severity.MEDIUM,
                    "Two tools/list snapshots differ without an observed list-changed event.",
                    evidence={
                        "first_names": sorted(str(tool.get("name")) for tool in first_objects),
                        "second_names": sorted(str(tool.get("name")) for tool in second_objects),
                    },
                    remediation="Make changes explicit, version manifests, emit list-changed notifications, and require re-review for privilege expansion.",
                )
            )

    return findings


def build_report(evidence: ProbeEvidence) -> CheckReport:
    findings = []
    seen: set[tuple[str, str, str]] = set()
    for finding in evaluate(evidence):
        signature = (
            finding.rule_id,
            finding.message,
            json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False),
        )
        if signature not in seen:
            seen.add(signature)
            findings.append(finding)
    findings.sort(key=lambda item: (-item.severity.rank, item.rule_id, item.message))
    diagnostics = evidence.diagnostic_observations or {
        "protocol_noise": {
            "total": len(evidence.protocol_noise),
            "retained": len(evidence.protocol_noise),
            "truncated": False,
        },
        "stderr": {
            "total": len(evidence.stderr_lines),
            "retained": len(evidence.stderr_lines),
            "truncated": False,
        },
        "unsolicited_messages": {
            "total": len(evidence.unsolicited_messages),
            "retained": len(evidence.unsolicited_messages),
            "truncated": False,
            "content_summarized": False,
        },
    }
    stderr_diagnostics = diagnostics.get("stderr", {})
    unsolicited_diagnostics = diagnostics.get("unsolicited_messages", {})
    stderr_count = stderr_diagnostics.get("total", len(evidence.stderr_lines))
    unsolicited_count = unsolicited_diagnostics.get(
        "total", len(evidence.unsolicited_messages)
    )
    return CheckReport(
        target=evidence.target,
        requested_protocol_version=evidence.requested_protocol_version,
        negotiated_protocol_version=evidence.negotiated_protocol_version,
        server_info=evidence.server_info,
        findings=findings,
        observations={
            "transport": evidence.transport,
            "safe_probe_methods": [
                "initialize",
                "notifications/initialized",
                "ping",
                "tools/list (bounded pagination; complete snapshot twice)",
                "resources/list (bounded pagination when declared)",
                "resources/templates/list (bounded pagination when resources declared)",
                "prompts/list (bounded pagination when declared)",
                "unknown method",
            ]
            + (
                [
                    "invalid Origin",
                    "GET listener headers",
                    "invalid protocol version",
                    "missing session header",
                    "DELETE session cleanup",
                ]
                if evidence.transport == "http"
                else []
            ),
            "transport_checks": evidence.transport_observations,
            "diagnostics": diagnostics,
            "capability_checks": evidence.capability_observations,
            "pagination_checks": evidence.pagination_observations,
            "discovered_tool_count": len(evidence.all_tools),
            "discovered_resource_count": len(
                ProbeEvidence._items_from_pages(
                    evidence.resources_list_pages, "resources"
                )
            ),
            "discovered_resource_template_count": len(
                ProbeEvidence._items_from_pages(
                    evidence.resource_templates_list_pages, "resourceTemplates"
                )
            ),
            "discovered_prompt_count": len(
                ProbeEvidence._items_from_pages(evidence.prompts_list_pages, "prompts")
            ),
            "stderr_line_count": stderr_count,
            "unsolicited_message_count": unsolicited_count,
            "tools_were_executed": False,
            "resources_were_read": False,
            "prompts_were_resolved": False,
        },
    )
