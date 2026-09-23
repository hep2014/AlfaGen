"""Small HTTP/1.1 benchmark client, not a production HTTP adapter.

One connection and one outstanding request; supports Content-Length responses.
Header and body are written together to avoid measuring client packet scheduling.
"""
import asyncio
import json
from urllib.parse import urlsplit

import httpx


class RawConnection:
    def __init__(self, base_url, tls_context, timeout=10):
        self.url = urlsplit(str(base_url))
        self.tls_context, self.timeout = tls_context, timeout
        self.writer = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self._close()

    async def _close(self):
        writer, self.writer = self.writer, None
        self.reader = None
        if writer is not None:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass

    async def post(self, path, *, json):
        try:
            async with asyncio.timeout(self.timeout):
                return await self._post(path, json)
        except asyncio.CancelledError:
            await self._close()
            raise
        except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError) as exc:
            await self._close()
            raise httpx.TransportError("benchmark_transport_error") from exc

    async def _post(self, path, payload):
        if self.writer is None:
            tls = self.tls_context if self.url.scheme == "https" else None
            port = self.url.port or (443 if tls else 80)
            self.reader, self.writer = await asyncio.open_connection(self.url.hostname, port, ssl=tls)
        body = json.dumps(payload, ensure_ascii=False).encode()
        header = (f"POST {path} HTTP/1.1\r\nHost: {self.url.netloc}\r\n"
                  f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                  "Connection: keep-alive\r\n\r\n").encode()
        self.writer.write(header + body)
        await self.writer.drain()
        head = (await self.reader.readuntil(b"\r\n\r\n")).decode("latin1").split("\r\n")
        status_parts = head[0].split()
        if not status_parts or status_parts[0] not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("benchmark_invalid_status")
        status = int(status_parts[1])
        if not 200 <= status <= 599:
            raise ValueError("benchmark_invalid_status")
        headers = dict(line.split(":", 1) for line in head[1:] if ":" in line)
        headers = {k.lower(): v.strip() for k, v in headers.items()}
        if "transfer-encoding" in headers or "content-length" not in headers:
            raise ValueError("benchmark_requires_content_length")
        length = int(headers["content-length"])
        if not 0 <= length <= 32_000_000:
            raise ValueError("benchmark_response_limit")
        content = await self.reader.readexactly(length)
        if headers.get("connection", "").lower() == "close":
            await self._close()
        return httpx.Response(status, headers=headers, content=content)
