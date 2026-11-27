"""Server-Sent Events (SSE) broadcaster and streaming helpers for SOCLens Web."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from soclens.web.state import WebRuntimeState


def format_sse(
    event_type: str,
    data: Any,
    *,
    event_id: str | None = None,
) -> str:
    """Format a single SSE frame with JSON payload."""
    lines: list[str] = []
    if event_id:
        lines.append(f"id: {event_id}")
    clean_event = (event_type or "message").strip() or "message"
    lines.append(f"event: {clean_event}")
    if isinstance(data, str):
        payload_text = data
    else:
        payload_text = json.dumps(data, ensure_ascii=False, default=str)
    for data_line in payload_text.splitlines() or [""]:
        lines.append(f"data: {data_line}")
    return "\n".join(lines) + "\n\n"


@dataclass(eq=False)
class _Subscriber:
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[tuple[str, Any] | None]


class SSEEventBus:
    """Thread-safe pub-sub broadcaster bridging sync workers to async SSE clients."""

    def __init__(self, *, max_queue_size: int = 256) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[_Subscriber] = set()
        self._max_queue_size = max(16, int(max_queue_size))
        self._closed = False

    def subscribe(self) -> _Subscriber:
        """Register the current event loop as a subscriber."""
        loop = asyncio.get_running_loop()
        sub = _Subscriber(
            loop=loop,
            queue=asyncio.Queue(maxsize=self._max_queue_size),
        )
        with self._lock:
            if self._closed:
                sub.queue.put_nowait(None)
            else:
                self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        """Remove a subscriber on client disconnect."""
        with self._lock:
            self._subscribers.discard(sub)

    def _enqueue_on_subscriber(self, sub: _Subscriber, item: tuple[str, Any] | None) -> None:
        if sub.loop.is_closed():
            return

        def _put() -> None:
            if sub.queue.full():
                try:
                    sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                sub.queue.put_nowait(item)
            except asyncio.QueueFull:
                pass

        try:
            sub.loop.call_soon_threadsafe(_put)
        except RuntimeError:
            pass

    def publish(self, event_type: str, data: Any) -> None:
        """Publish an SSE event from any thread or event loop."""
        with self._lock:
            if self._closed:
                return
            subs = list(self._subscribers)
        item = (event_type, data)
        for sub in subs:
            self._enqueue_on_subscriber(sub, item)

    def close_all(self) -> None:
        """Emit a shutdown event and terminate all active SSE streams."""
        with self._lock:
            self._closed = True
            subs = list(self._subscribers)
            self._subscribers.clear()
        for sub in subs:
            self._enqueue_on_subscriber(sub, ("shutdown", {"ok": True, "shutting_down": True}))
            self._enqueue_on_subscriber(sub, None)


def create_events_stream_response(
    request: Request,
    runtime: WebRuntimeState,
    *,
    keepalive_seconds: float = 15.0,
) -> StreamingResponse:
    """Build a ``text/event-stream`` response for ``GET /api/events/stream``."""
    once_param = str(request.query_params.get("once", "")).strip().lower()
    once = once_param in ("1", "true", "yes")

    async def _event_generator() -> AsyncIterator[str]:
        initial_status = runtime.get_status_payload()
        yield format_sse("status", initial_status, event_id=f"status-{int(time.time() * 1000)}")
        if once or runtime.shutdown_event.is_set():
            return

        sub = runtime.sse_bus.subscribe()
        try:
            while not runtime.shutdown_event.is_set():
                try:
                    item = await asyncio.wait_for(sub.queue.get(), timeout=keepalive_seconds)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if item is None:
                    break
                ev_type, ev_data = item
                yield format_sse(ev_type, ev_data)
                if ev_type == "shutdown":
                    break
        except asyncio.CancelledError:
            pass
        finally:
            runtime.sse_bus.unsubscribe(sub)

    return StreamingResponse(
        _event_generator(),
        status_code=200,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
