"""Async line-delimited JSON-RPC 2.0 transport over a child process stdio."""

from __future__ import annotations

import asyncio
import json
from typing import Any


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
    ) -> None:
        if not command:
            raise ValueError("stdio command cannot be empty")
        self.command = command
        self.timeout = timeout
        self.stream_limit = stream_limit
        self.process: asyncio.subprocess.Process | None = None
        self.protocol_noise: list[str] = []
        self.stderr_lines: list[str] = []
        self.unsolicited_messages: list[dict[str, Any]] = []
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._next_id = 1
        self._write_lock = asyncio.Lock()
        self._stdout_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None

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
                    self.protocol_noise.append(line)
                    continue
                if not isinstance(message, dict):
                    self.protocol_noise.append(line)
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
                    self.unsolicited_messages.append(message)
        except (ValueError, asyncio.LimitOverrunError) as error:
            self.protocol_noise.append(f"<stdout framing error: {error}>")
        finally:
            error = TransportError("target stdout closed before the response arrived")
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(error)

    async def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while raw_line := await self.process.stderr.readline():
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            self.stderr_lines.append(line)
            if len(self.stderr_lines) > 200:
                del self.stderr_lines[: len(self.stderr_lines) - 200]

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
