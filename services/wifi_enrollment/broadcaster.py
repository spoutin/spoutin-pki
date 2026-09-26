import asyncio
import json
import logging
import threading
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Thread-safe Server-Sent Events (SSE) broadcaster for admins and enrollment clients."""

    def __init__(self):
        self._lock = threading.Lock()
        self._admin_subscribers: set[asyncio.Queue] = set()
        self._request_subscribers: dict[str, set[asyncio.Queue]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _deliver_message(self, q: asyncio.Queue, msg: str) -> None:
        try:
            if self._loop and self._loop.is_running():
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None

                if current_loop is self._loop:
                    q.put_nowait(msg)
                else:
                    self._loop.call_soon_threadsafe(q.put_nowait, msg)
            else:
                q.put_nowait(msg)
        except Exception as e:
            logger.debug(f"Failed to deliver SSE message: {e}")

    def publish_admin(self, event: str, data: dict[str, Any]) -> None:
        """Broadcasts an event to all connected admin portals."""
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            subscribers = list(self._admin_subscribers)
        for q in subscribers:
            self._deliver_message(q, payload)

    def publish_request(self, request_id: str, event: str, data: dict[str, Any]) -> None:
        """Publishes an event to clients waiting for a specific request_id."""
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            subscribers = list(self._request_subscribers.get(request_id, []))
        for q in subscribers:
            self._deliver_message(q, payload)

    async def subscribe_admin(self) -> AsyncGenerator[str, None]:
        """Async generator yielding SSE messages for admin subscribers."""
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._admin_subscribers.add(q)
        try:
            yield f"event: connected\ndata: {json.dumps({'status': 'connected'})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            with self._lock:
                self._admin_subscribers.discard(q)

    async def subscribe_request(self, request_id: str) -> AsyncGenerator[str, None]:
        """Async generator yielding SSE messages for a specific enrollment request."""
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            if request_id not in self._request_subscribers:
                self._request_subscribers[request_id] = set()
            self._request_subscribers[request_id].add(q)
        try:
            yield f"event: connected\ndata: {json.dumps({'request_id': request_id})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            with self._lock:
                if request_id in self._request_subscribers:
                    self._request_subscribers[request_id].discard(q)
                    if not self._request_subscribers[request_id]:
                        del self._request_subscribers[request_id]
