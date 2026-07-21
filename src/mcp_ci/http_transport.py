"""Bounded JSON-RPC client for the MCP Streamable HTTP transport."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .transport import TransportError


JSON_CONTENT_TYPE = "application/json"
SSE_CONTENT_TYPE = "text/event-stream"
DEFAULT_BODY_LIMIT = 1024 * 1024


def _is_loopback(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_visible_ascii(value: str) -> bool:
    return bool(value) and all(0x21 <= ord(character) <= 0x7E for character in value)


def validate_http_url(value: str) -> str:
    """Apply the checker's narrow endpoint and cleartext transport policy."""

    url = value.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("--http URL must use http or https")
    if parsed.hostname is None:
        raise ValueError("--http URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("--http URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("--http URL must not contain a fragment")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError(f"--http URL has an invalid port: {error}") from error
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise ValueError("plain HTTP is allowed only for loopback MCP endpoints")
    return url


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class HttpExchange:
    """Sanitized-enough internal representation of one HTTP response."""

    method: str
    operation: str
    status: int
    headers: dict[str, str]
    content_type: str
    body_size: int
    messages: tuple[dict[str, Any], ...] = ()
    parse_errors: tuple[str, ...] = ()

    def response_for(self, request_id: int | str) -> dict[str, Any] | None:
        for message in self.messages:
            is_response = "method" not in message and (
                "result" in message or "error" in message
            )
            if is_response and message.get("id") == request_id:
                return message
        return None


def _content_type(headers: dict[str, str]) -> str:
    return headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _parse_json_body(body: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    if not body:
        return [], []
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return [], [f"invalid JSON response body: {error}"]
    if not isinstance(payload, dict):
        return [], ["JSON response body is not one JSON-RPC object"]
    return [payload], []


def _consume_sse_event(
    data_lines: list[str],
    messages: list[dict[str, Any]],
    errors: list[str],
) -> None:
    if not data_lines:
        return
    data = "\n".join(data_lines)
    if not data:
        return
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as error:
        errors.append(f"invalid SSE data JSON: {error}")
        return
    if not isinstance(payload, dict):
        errors.append("SSE data is not one JSON-RPC object")
        return
    messages.append(payload)


def _read_sse(
    response: Any,
    *,
    body_limit: int,
    expected_id: int | str | None,
) -> tuple[int, list[dict[str, Any]], list[str]]:
    total = 0
    data_lines: list[str] = []
    messages: list[dict[str, Any]] = []
    errors: list[str] = []
    while True:
        raw_line = response.readline(body_limit - total + 1)
        if not raw_line:
            _consume_sse_event(data_lines, messages, errors)
            break
        total += len(raw_line)
        if total > body_limit:
            raise TransportError(
                f"HTTP response exceeded the {body_limit}-byte inspection limit"
            )
        try:
            line = raw_line.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as error:
            errors.append(f"invalid UTF-8 in SSE stream: {error}")
            continue
        if line == "":
            _consume_sse_event(data_lines, messages, errors)
            data_lines = []
            if expected_id is not None:
                exchange = HttpExchange(
                    method="POST",
                    operation="sse",
                    status=200,
                    headers={},
                    content_type=SSE_CONTENT_TYPE,
                    body_size=total,
                    messages=tuple(messages),
                )
                if exchange.response_for(expected_id) is not None:
                    break
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
    return total, messages, errors


class JsonRpcHttpClient:
    """Small sequential client for bounded Streamable HTTP conformance probes."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        body_limit: int = DEFAULT_BODY_LIMIT,
    ) -> None:
        self.url = validate_http_url(url)
        self.timeout = timeout
        self.body_limit = body_limit
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self.unsolicited_messages: list[dict[str, Any]] = []
        self.protocol_noise: list[str] = []
        self.exchanges: list[HttpExchange] = []
        self.last_exchange: HttpExchange | None = None
        self._next_id = 1
        self._opener = build_opener(_NoRedirect())

    def _request_message(
        self, method: str, params: dict[str, Any] | None
    ) -> tuple[int, dict[str, Any]]:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params
        return request_id, message

    def _headers(
        self,
        *,
        accept: str,
        content_type: bool,
        origin: str | None,
        include_session: bool,
        include_protocol: bool,
        protocol_version: str | None,
    ) -> dict[str, str]:
        headers = {"Accept": accept}
        if content_type:
            headers["Content-Type"] = JSON_CONTENT_TYPE
        if origin is not None:
            headers["Origin"] = origin
        if (
            include_session
            and self.session_id is not None
            and _is_visible_ascii(self.session_id)
        ):
            headers["MCP-Session-Id"] = self.session_id
        version = protocol_version or self.protocol_version
        if include_protocol and version is not None and _is_visible_ascii(version):
            headers["MCP-Protocol-Version"] = version
        return headers

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_id, message = self._request_message(method, params)
        exchange = await self.post_json(
            message,
            include_protocol=method != "initialize",
            expected_id=request_id,
        )
        if method == "initialize":
            self.session_id = exchange.headers.get("mcp-session-id")
        response = exchange.response_for(request_id)
        for candidate in exchange.messages:
            if candidate is not response:
                self.unsolicited_messages.append(candidate)
        if response is None:
            return {}
        if method == "initialize":
            result = response.get("result")
            if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
                self.protocol_version = result["protocolVersion"]
        return response

    async def notify(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self.post_json(message)

    async def probe_request(
        self,
        method: str,
        *,
        origin: str | None = None,
        include_session: bool = True,
        include_protocol: bool = True,
        protocol_version: str | None = None,
    ) -> HttpExchange:
        request_id, message = self._request_message(method, None)
        return await self.post_json(
            message,
            origin=origin,
            include_session=include_session,
            include_protocol=include_protocol,
            protocol_version=protocol_version,
            expected_id=request_id,
        )

    async def post_json(
        self,
        message: dict[str, Any],
        *,
        origin: str | None = None,
        include_session: bool = True,
        include_protocol: bool = True,
        protocol_version: str | None = None,
        expected_id: int | str | None = None,
    ) -> HttpExchange:
        body = json.dumps(
            message, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        headers = self._headers(
            accept=f"{JSON_CONTENT_TYPE}, {SSE_CONTENT_TYPE}",
            content_type=True,
            origin=origin,
            include_session=include_session,
            include_protocol=include_protocol,
            protocol_version=protocol_version,
        )
        return await self._exchange(
            "POST",
            operation=(
                str(message.get("method"))
                if isinstance(message.get("method"), str)
                else "json-rpc-response"
            ),
            headers=headers,
            body=body,
            expected_id=expected_id,
        )

    async def inspect_get(self) -> HttpExchange:
        headers = self._headers(
            accept=SSE_CONTENT_TYPE,
            content_type=False,
            origin=None,
            include_session=True,
            include_protocol=True,
            protocol_version=None,
        )
        return await self._exchange(
            "GET", operation="http/get-listener", headers=headers, read_body=False
        )

    async def delete_session(self) -> HttpExchange:
        headers = self._headers(
            accept=f"{JSON_CONTENT_TYPE}, {SSE_CONTENT_TYPE}",
            content_type=False,
            origin=None,
            include_session=True,
            include_protocol=True,
            protocol_version=None,
        )
        return await self._exchange(
            "DELETE", operation="http/delete-session", headers=headers
        )

    async def _exchange(
        self,
        method: str,
        *,
        operation: str,
        headers: dict[str, str],
        body: bytes | None = None,
        expected_id: int | str | None = None,
        read_body: bool = True,
    ) -> HttpExchange:
        exchange = await asyncio.to_thread(
            self._exchange_sync,
            method,
            operation,
            headers,
            body,
            expected_id,
            read_body,
        )
        self.exchanges.append(exchange)
        self.last_exchange = exchange
        self.protocol_noise.extend(exchange.parse_errors)
        return exchange

    def _exchange_sync(
        self,
        method: str,
        operation: str,
        headers: dict[str, str],
        body: bytes | None,
        expected_id: int | str | None,
        read_body: bool,
    ) -> HttpExchange:
        request = Request(self.url, data=body, headers=headers, method=method)
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except HTTPError as error:
            response = error
        except (OSError, URLError, TimeoutError) as error:
            raise TransportError(f"HTTP {method} request failed: {error}") from error

        with response:
            status = int(response.status)
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            content_type = _content_type(response_headers)
            body_size = 0
            messages: list[dict[str, Any]] = []
            parse_errors: list[str] = []
            if read_body:
                if content_type == SSE_CONTENT_TYPE:
                    body_size, messages, parse_errors = _read_sse(
                        response,
                        body_limit=self.body_limit,
                        expected_id=expected_id,
                    )
                else:
                    body_bytes = response.read(self.body_limit + 1)
                    body_size = len(body_bytes)
                    if body_size > self.body_limit:
                        raise TransportError(
                            f"HTTP response exceeded the {self.body_limit}-byte inspection limit"
                        )
                    if content_type == JSON_CONTENT_TYPE:
                        messages, parse_errors = _parse_json_body(body_bytes)
            return HttpExchange(
                method=method,
                operation=operation,
                status=status,
                headers=response_headers,
                content_type=content_type,
                body_size=body_size,
                messages=tuple(messages),
                parse_errors=tuple(parse_errors),
            )
