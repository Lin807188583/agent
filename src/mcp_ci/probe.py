"""Safe MCP lifecycle and discovery probe.

The probe intentionally never calls a discovered tool. Tool annotations are
hints, not an authorization boundary, so black-box execution would be unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from . import __version__
from .http_transport import HttpExchange, JsonRpcHttpClient
from .transport import JsonRpcStdioClient


MAX_LIST_PAGES = 20


@dataclass(slots=True)
class ProbeEvidence:
    target: str
    requested_protocol_version: str
    transport: str = "stdio"
    initialize_response: dict[str, Any] = field(default_factory=dict)
    ping_response: dict[str, Any] = field(default_factory=dict)
    first_tools_response: dict[str, Any] = field(default_factory=dict)
    second_tools_response: dict[str, Any] = field(default_factory=dict)
    tools_list_pages: list[dict[str, Any]] = field(default_factory=list)
    second_tools_list_pages: list[dict[str, Any]] = field(default_factory=list)
    resources_list_pages: list[dict[str, Any]] = field(default_factory=list)
    resource_templates_list_pages: list[dict[str, Any]] = field(default_factory=list)
    prompts_list_pages: list[dict[str, Any]] = field(default_factory=list)
    pagination_observations: dict[str, Any] = field(default_factory=dict)
    capability_observations: dict[str, Any] = field(default_factory=dict)
    unknown_method_response: dict[str, Any] = field(default_factory=dict)
    protocol_noise: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    unsolicited_messages: list[dict[str, Any]] = field(default_factory=list)
    diagnostic_observations: dict[str, Any] = field(default_factory=dict)
    transport_observations: dict[str, Any] = field(default_factory=dict)

    @property
    def initialize_result(self) -> dict[str, Any]:
        result = self.initialize_response.get("result")
        return result if isinstance(result, dict) else {}

    @property
    def negotiated_protocol_version(self) -> str | None:
        value = self.initialize_result.get("protocolVersion")
        return value if isinstance(value, str) else None

    @property
    def server_info(self) -> dict[str, Any]:
        value = self.initialize_result.get("serverInfo")
        return value if isinstance(value, dict) else {}

    @property
    def capabilities(self) -> dict[str, Any]:
        value = self.initialize_result.get("capabilities")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _tools_from(response: dict[str, Any]) -> list[dict[str, Any]]:
        result = response.get("result")
        if not isinstance(result, dict):
            return []
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        return [tool for tool in tools if isinstance(tool, dict)]

    @property
    def first_tools(self) -> list[dict[str, Any]]:
        return self._tools_from(self.first_tools_response)

    @property
    def second_tools(self) -> list[dict[str, Any]]:
        return self._tools_from(self.second_tools_response)

    @staticmethod
    def _items_from_pages(
        pages: list[dict[str, Any]], item_key: str
    ) -> list[Any]:
        items: list[Any] = []
        for page in pages:
            result = page.get("result")
            if isinstance(result, dict):
                value = result.get(item_key)
                if isinstance(value, list):
                    items.extend(value)
        return items

    @property
    def all_tools(self) -> list[Any]:
        pages = self.tools_list_pages or [self.first_tools_response]
        return self._items_from_pages(pages, "tools")


class _ProbeClient(Protocol):
    protocol_noise: list[str]
    unsolicited_messages: list[dict[str, Any]]

    async def request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...

    async def notify(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None: ...


async def _safe_lifecycle(
    client: _ProbeClient,
    requested_protocol_version: str,
) -> dict[str, Any]:
    """Run transport-neutral lifecycle and discovery without calling a Tool."""

    initialize_response = await client.request(
        "initialize",
        {
            "protocolVersion": requested_protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "mcp-ci-demo", "version": __version__},
        },
    )
    ping_response: dict[str, Any] = {}
    first_tools_response: dict[str, Any] = {}
    second_tools_response: dict[str, Any] = {}
    tools_list_pages: list[dict[str, Any]] = []
    second_tools_list_pages: list[dict[str, Any]] = []
    resources_list_pages: list[dict[str, Any]] = []
    resource_templates_list_pages: list[dict[str, Any]] = []
    prompts_list_pages: list[dict[str, Any]] = []
    pagination_observations: dict[str, Any] = {}
    capability_observations: dict[str, Any] = {}
    unknown_method_response: dict[str, Any] = {}
    if isinstance(initialize_response.get("result"), dict):
        await client.notify("notifications/initialized")
        ping_response = await client.request("ping")
        initialize_result = initialize_response["result"]
        capabilities = initialize_result.get("capabilities", {})
        capability_observations = _observe_capabilities(capabilities)
        if isinstance(capabilities, dict):
            if isinstance(capabilities.get("tools"), dict):
                tools_list_pages, pagination_observations["tools"] = (
                    await _safe_list_flow(client, "tools/list", "tools")
                )
                second_tools_list_pages, second_observation = await _safe_list_flow(
                    client, "tools/list", "tools"
                )
                pagination_observations["tools_second_snapshot"] = second_observation
                if tools_list_pages:
                    first_tools_response = tools_list_pages[0]
                if second_tools_list_pages:
                    second_tools_response = second_tools_list_pages[0]
            if isinstance(capabilities.get("resources"), dict):
                resources_list_pages, pagination_observations["resources"] = (
                    await _safe_list_flow(client, "resources/list", "resources")
                )
                resource_templates_list_pages, pagination_observations[
                    "resource_templates"
                ] = await _safe_list_flow(
                    client, "resources/templates/list", "resourceTemplates"
                )
            if isinstance(capabilities.get("prompts"), dict):
                prompts_list_pages, pagination_observations["prompts"] = (
                    await _safe_list_flow(client, "prompts/list", "prompts")
                )
        unknown_method_response = await client.request("mcp-ci/unknown-method-probe")
    return {
        "initialize_response": initialize_response,
        "ping_response": ping_response,
        "first_tools_response": first_tools_response,
        "second_tools_response": second_tools_response,
        "tools_list_pages": tools_list_pages,
        "second_tools_list_pages": second_tools_list_pages,
        "resources_list_pages": resources_list_pages,
        "resource_templates_list_pages": resource_templates_list_pages,
        "prompts_list_pages": prompts_list_pages,
        "pagination_observations": pagination_observations,
        "capability_observations": capability_observations,
        "unknown_method_response": unknown_method_response,
    }


def _observe_capabilities(value: Any) -> dict[str, Any]:
    """Return capability facts without copying opaque or sensitive values."""

    if not isinstance(value, dict):
        return {"capabilities_type": type(value).__name__}
    observations: dict[str, Any] = {
        "capabilities_type": "object",
        "declared": sorted(str(key) for key in value),
    }
    for name in ("tools", "resources", "prompts"):
        if name not in value:
            continue
        capability = value[name]
        entry: dict[str, Any] = {"type": type(capability).__name__}
        if isinstance(capability, dict) and "listChanged" in capability:
            entry["list_changed_type"] = type(capability["listChanged"]).__name__
            if isinstance(capability["listChanged"], bool):
                entry["list_changed"] = capability["listChanged"]
        observations[name] = entry
    return observations


async def _safe_list_flow(
    client: _ProbeClient,
    method: str,
    item_key: str,
    *,
    max_pages: int = MAX_LIST_PAGES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect one paginated list while treating every cursor as opaque."""

    pages: list[dict[str, Any]] = []
    page_shapes: list[dict[str, Any]] = []
    seen_cursors: set[str] = set()
    params: dict[str, Any] | None = None
    termination = "missing-next-cursor"
    total_items = 0

    while len(pages) < max_pages:
        response = await client.request(method, params)
        pages.append(response)
        result = response.get("result")
        shape: dict[str, Any] = {
            "result_type": type(result).__name__,
            "item_key": item_key,
            "item_type": None,
            "item_count": None,
            "object_item_count": None,
            "next_cursor_present": False,
            "next_cursor_type": None,
        }
        if not isinstance(result, dict):
            shape["result_type"] = type(result).__name__
            page_shapes.append(shape)
            termination = "invalid-result"
            break
        items = result.get(item_key)
        shape["item_type"] = type(items).__name__
        if not isinstance(items, list):
            page_shapes.append(shape)
            termination = "invalid-items"
            break
        object_item_count = sum(isinstance(item, dict) for item in items)
        shape["item_count"] = len(items)
        shape["object_item_count"] = object_item_count
        total_items += len(items)
        next_cursor = result.get("nextCursor")
        shape["next_cursor_present"] = "nextCursor" in result
        shape["next_cursor_type"] = type(next_cursor).__name__
        page_shapes.append(shape)
        if "nextCursor" not in result:
            termination = "complete"
            break
        if not isinstance(next_cursor, str):
            termination = "invalid-cursor"
            break
        if next_cursor in seen_cursors:
            termination = "repeated-cursor"
            break
        seen_cursors.add(next_cursor)
        params = {"cursor": next_cursor}
    else:
        termination = "max-pages"

    return pages, {
        "page_count": len(pages),
        "item_count": total_items,
        "termination": termination,
        "page_shapes": page_shapes,
    }


def _build_evidence(
    *,
    client: _ProbeClient,
    target: str,
    requested_protocol_version: str,
    transport: str,
    responses: dict[str, Any],
    stderr_lines: list[str] | None = None,
    transport_observations: dict[str, Any] | None = None,
) -> ProbeEvidence:
    retained_stderr = list(stderr_lines or [])
    diagnostics = getattr(client, "diagnostic_observations", None)
    if not isinstance(diagnostics, dict):
        diagnostics = {
            "protocol_noise": {
                "total": len(client.protocol_noise),
                "retained": len(client.protocol_noise),
                "truncated": False,
            },
            "stderr": {
                "total": len(retained_stderr),
                "retained": len(retained_stderr),
                "truncated": False,
            },
            "unsolicited_messages": {
                "total": len(client.unsolicited_messages),
                "retained": len(client.unsolicited_messages),
                "truncated": False,
                "content_summarized": False,
            },
        }
    return ProbeEvidence(
        target=target,
        requested_protocol_version=requested_protocol_version,
        transport=transport,
        initialize_response=responses["initialize_response"],
        ping_response=responses["ping_response"],
        first_tools_response=responses["first_tools_response"],
        second_tools_response=responses["second_tools_response"],
        tools_list_pages=list(responses.get("tools_list_pages", [])),
        second_tools_list_pages=list(responses.get("second_tools_list_pages", [])),
        resources_list_pages=list(responses.get("resources_list_pages", [])),
        resource_templates_list_pages=list(
            responses.get("resource_templates_list_pages", [])
        ),
        prompts_list_pages=list(responses.get("prompts_list_pages", [])),
        pagination_observations=dict(responses.get("pagination_observations", {})),
        capability_observations=dict(responses.get("capability_observations", {})),
        unknown_method_response=responses["unknown_method_response"],
        protocol_noise=list(client.protocol_noise),
        stderr_lines=retained_stderr,
        unsolicited_messages=list(client.unsolicited_messages),
        diagnostic_observations=diagnostics,
        transport_observations=transport_observations or {},
    )


async def run_stdio_probe(
    command: list[str],
    *,
    target: str,
    requested_protocol_version: str = "2025-11-25",
    timeout: float = 5.0,
) -> ProbeEvidence:
    """Launch a target and collect evidence using only discovery operations."""

    client = JsonRpcStdioClient(command, timeout=timeout)
    async with client:
        responses = await _safe_lifecycle(client, requested_protocol_version)

    return _build_evidence(
        client=client,
        target=target,
        requested_protocol_version=requested_protocol_version,
        transport="stdio",
        responses=responses,
        stderr_lines=client.stderr_lines,
    )


def _first_exchange(
    exchanges: list[HttpExchange], operation: str
) -> HttpExchange | None:
    return next(
        (exchange for exchange in exchanges if exchange.operation == operation),
        None,
    )


async def run_http_probe(
    url: str,
    *,
    target: str,
    requested_protocol_version: str = "2025-11-25",
    timeout: float = 5.0,
) -> ProbeEvidence:
    """Collect bounded Streamable HTTP lifecycle and hardening evidence."""

    client = JsonRpcHttpClient(url, timeout=timeout)
    origin_exchange = await client.probe_request(
        "ping",
        origin="https://attacker.invalid",
        include_session=False,
        include_protocol=False,
    )
    lifecycle_start = len(client.exchanges)
    responses = await _safe_lifecycle(client, requested_protocol_version)
    lifecycle_exchanges = client.exchanges[lifecycle_start:]

    get_exchange: HttpExchange | None = None
    invalid_protocol_exchange: HttpExchange | None = None
    missing_session_exchange: HttpExchange | None = None
    delete_exchange: HttpExchange | None = None
    initialized = isinstance(responses["initialize_response"].get("result"), dict)
    if initialized:
        get_exchange = await client.inspect_get()
        invalid_protocol_exchange = await client.probe_request(
            "ping",
            protocol_version="mcp-ci-invalid-version",
        )
        if client.session_id is not None:
            missing_session_exchange = await client.probe_request(
                "ping",
                include_session=False,
            )
            delete_exchange = await client.delete_session()

    initialize_exchange = _first_exchange(lifecycle_exchanges, "initialize")
    notification_exchange = _first_exchange(
        lifecycle_exchanges, "notifications/initialized"
    )
    response_content_types = [
        {
            "method": exchange.operation,
            "status": exchange.status,
            "content_type": exchange.content_type,
        }
        for exchange in lifecycle_exchanges
        if not exchange.operation.startswith("notifications/")
    ]
    session_id = client.session_id
    observations = {
        "origin_status": origin_exchange.status,
        "initialize_status": (
            initialize_exchange.status if initialize_exchange is not None else None
        ),
        "initialize_content_type": (
            initialize_exchange.content_type
            if initialize_exchange is not None
            else ""
        ),
        "response_content_types": response_content_types,
        "parse_error_count": sum(
            len(exchange.parse_errors) for exchange in lifecycle_exchanges
        ),
        "notification_status": (
            notification_exchange.status if notification_exchange is not None else None
        ),
        "notification_body_size": (
            notification_exchange.body_size
            if notification_exchange is not None
            else None
        ),
        "get_status": get_exchange.status if get_exchange is not None else None,
        "get_content_type": (
            get_exchange.content_type if get_exchange is not None else ""
        ),
        "invalid_protocol_status": (
            invalid_protocol_exchange.status
            if invalid_protocol_exchange is not None
            else None
        ),
        "session_id_issued": session_id is not None,
        "session_id_length": len(session_id) if session_id is not None else 0,
        "session_id_visible_ascii": (
            all(0x21 <= ord(character) <= 0x7E for character in session_id)
            if session_id is not None
            else None
        ),
        "missing_session_status": (
            missing_session_exchange.status
            if missing_session_exchange is not None
            else None
        ),
        "delete_status": (
            delete_exchange.status if delete_exchange is not None else None
        ),
    }
    return _build_evidence(
        client=client,
        target=target,
        requested_protocol_version=requested_protocol_version,
        transport="http",
        responses=responses,
        transport_observations=observations,
    )
