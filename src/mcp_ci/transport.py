"""Async line-delimited JSON-RPC 2.0 transport over a child process stdio."""

from __future__ import annotations

import asyncio
import json
from typing import Any


DEFAULT_DIAGNOSTIC_LIMIT = 200
DEFAULT_DIAGNOSTIC_TEXT_LIMIT = 4096


class TransportError(RuntimeError):
    """The child process or JSON-RPC transport could not complete an operation."""


class JsonRpcStdioClient:
    """Small MCP-oriented stdio client with request-ID correlation.

    MCP reserves stdout for protocol messages. Lines that are not JSON objects
    are retained as evidence instead of being silently discarded.
    """

    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = 5.0,
        stream_limit: int = 1024 * 1024,
        diagnostic_limit: int = DEFAULT_DIAGNOSTIC_LIMIT,
        diagnostic_text_limit: int = DEFAULT_DIAGNOSTIC_TEXT_LIMIT,
    ) -> None:
        if not command:
            raise ValueError("stdio command cannot be empty")
        if diagnostic_limit <= 0:
            raise ValueError("diagnostic_limit must be greater than zero")
        if diagnostic_text_limit <= 0:
            raise ValueError("diagnostic_text_limit must be greater than zero")
        self.command = command
        self.timeout = timeout
        self.stream_limit = stream_limit
        self.diagnostic_limit = diagnostic_limit
        self.diagnostic_text_limit = diagnostic_text_limit
        self.process: asyncio.subprocess.Process | None = None
        self.protocol_noise: list[str] = []
        self.stderr_lines: list[str] = []
        self.unsolicited_messages: list[dict[str, Any]] = []
        self.protocol_noise_count = 0
        self.stderr_line_count = 0
        self.unsolicited_message_count = 0
        self._protocol_noise_truncated = False
        self._stderr_truncated = False
        self._unsolicited_messages_truncated = False
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._next_id = 1
        self._write_lock = asyncio.Lock()
        self._stdout_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None

    def _truncate_text(self, value: str) -> tuple[str, bool]:
        if len(value) <= self.diagnostic_text_limit:
            return value, False
        if self.diagnostic_text_limit == 1:
            return "…", True
        return value[: self.diagnostic_text_limit - 1] + "…", True

    def _record_protocol_noise(self, value: str) -> None:
        self.protocol_noise_count += 1
        sample, text_truncated = self._truncate_text(value)
        self._protocol_noise_truncated |= text_truncated
        if len(self.protocol_noise) < self.diagnostic_limit:
            self.protocol_noise.append(sample)
        else:
            self._protocol_noise_truncated = True

    def _record_stderr(self, value: str) -> None:
        self.stderr_line_count += 1
        sample, text_truncated = self._truncate_text(value)
        self._stderr_truncated |= text_truncated
        self.stderr_lines.append(sample)
        if len(self.stderr_lines) > self.diagnostic_limit:
            del self.stderr_lines[: len(self.stderr_lines) - self.diagnostic_limit]
            self._stderr_truncated = True

    def _summarize_unsolicited(self, message: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "has_params": "params" in message,
            "has_result": "result" in message,
            "has_error": "error" in message,
        }
        for key in ("jsonrpc", "id", "method"):
            if key not in message:
                continue
            value = message[key]
            if isinstance(value, str):
                summary[key] = self._truncate_text(value)[0]
            elif value is None or isinstance(value, (bool, int, float)):
                summary[key] = value
            else:
                summary[f"{key}_type"] = type(value).__name__
        return summary

    def _record_unsolicited(self, message: dict[str, Any]) -> None:
        self.unsolicited_message_count += 1
        if len(self.unsolicited_messages) < self.diagnostic_limit:
            self.unsolicited_messages.append(self._summarize_unsolicited(message))
        else:
            self._unsolicited_messages_truncated = True

    @property
    def diagnostic_observations(self) -> dict[str, dict[str, int | bool]]:
        return {
            "protocol_noise": {
                "total": self.protocol_noise_count,
                "retained": len(self.protocol_noise),
                "truncated": self._protocol_noise_truncated,
            },
            "stderr": {
                "total": self.stderr_line_count,
                "retained": len(self.stderr_lines),
                "truncated": self._stderr_truncated,
            },
            "unsolicited_messages": {
                "total": self.unsolicited_message_count,
                "retained": len(self.unsolicited_messages),
                "truncated": self._unsolicited_messages_truncated,
                "content_summarized": True,
            },
        }

    async def __aenter__(self) -> "JsonRpcStdioClient":
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self.process is not None:
            raise TransportError("transport has already been started")
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=self.stream_limit,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise TransportError(f"cannot start target command: {error}") from error
        self._stdout_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = future
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params
        try:
            await self._send(message)
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=self.timeout if timeout is None else timeout
            )
        except TimeoutError as error:
            if not future.done():
                future.cancel()
            raise TransportError(f"request {method!r} timed out") from error
        finally:
            self._pending.pop(request_id, None)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self._send(message)

    async def _send(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise TransportError("transport is not running")
        if self.process.returncode is not None:
            raise TransportError(f"target exited with code {self.process.returncode}")
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        async with self._write_lock:
            try:
                self.process.stdin.write(payload)
                await self.process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as error:
                raise TransportError("target closed stdin") from error

    async def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            while raw_line := await self.process.stdout.readline():
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    self._record_protocol_noise(line)
                    continue
                if not isinstance(message, dict):
                    self._record_protocol_noise(line)
                    continue
                response_id = message.get("id")
                future = self._pending.get(response_id)
                is_response = "method" not in message and (
                    "result" in message or "error" in message
                )
                if (
                    is_response
                    and response_id is not None
                    and future is not None
                    and not future.done()
                ):
                    future.set_result(message)
                else:
                    self._record_unsolicited(message)
        except (ValueError, asyncio.LimitOverrunError) as error:
            self._record_protocol_noise(f"<stdout framing error: {error}>")
        finally:
            error = TransportError("target stdout closed before the response arrived")
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(error)

    async def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while raw_line := await self.process.stderr.readline():
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            self._record_stderr(line)

    async def close(self) -> None:
        process = self.process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.is_closing():
            process.stdin.close()
            try:
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=0.5)
        except TimeoutError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=0.5)
            except TimeoutError:
                process.kill()
                await process.wait()
        for task in (self._stdout_task, self._stderr_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (self._stdout_task, self._stderr_task) if task is not None),
            return_exceptions=True,
        )
        self.process = None
