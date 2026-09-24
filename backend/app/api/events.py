"""In-process event bus for live investigation updates.

Why not a message broker: MailTrace runs as one process on one machine for a
demo and for a small SOC. Adding Redis would add an install step, a port and a
failure mode in exchange for nothing the UI can perceive. The bus is deliberately
bounded and lossy per subscriber - a browser tab that stops reading must not be
able to grow the server's memory, so its queue drops the oldest event instead.

Two consumers use this:

* the SSE endpoint (``GET /api/events``), which streams agent steps to the
  investigator screen as they happen;
* the polling fallback (``GET /api/events/since``), because a corporate proxy
  that buffers ``text/event-stream`` is common enough that the UI needs a way
  through that does not depend on streaming working.

Every event carries a monotonically increasing ``seq``, which is what makes the
polling fallback correct rather than approximate: the client asks for everything
after the highest sequence it has seen and cannot silently miss a step.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any, Dict, List, Optional

# Ring buffer of recent events, so a client that connects mid-investigation, or
# reconnects after a dropped stream, can catch up rather than showing a blank
# timeline. 400 is about twenty full investigations - long enough to be useful,
# small enough to be irrelevant to memory.
_HISTORY_LIMIT = 400
_QUEUE_LIMIT = 200


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: List["queue.Queue[Dict[str, Any]]"] = []
        self._history: List[Dict[str, Any]] = []
        self._seq = 0

    # -- publish -----------------------------------------------------------
    def publish(self, kind: str,
                payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "kind": kind, "at": time.time(),
                     "data": payload or {}}
            self._history.append(event)
            if len(self._history) > _HISTORY_LIMIT:
                del self._history[:-_HISTORY_LIMIT]
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Drop the oldest rather than the newest: a live view is more
                # useful showing recent steps with a gap than stalling on stale
                # ones. The client can always refetch the case bundle.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (queue.Empty, queue.Full):  # pragma: no cover - race only
                    pass
        return event

    def step_publisher(self, case_number: str) -> Any:
        """Return an ``on_step`` callable for :func:`app.pipeline.ingest_bytes`."""

        def on_step(step: Any) -> None:
            self.publish("step", {
                "case_number": case_number,
                "index": getattr(step, "index", 0),
                "action": getattr(step, "action", ""),
                "result": getattr(step, "result", ""),
                "reasoning": getattr(step, "reasoning", ""),
                "status": getattr(step, "status", "ok"),
            })

        return on_step

    # -- subscribe ---------------------------------------------------------
    def subscribe(self) -> "queue.Queue[Dict[str, Any]]":
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=_QUEUE_LIMIT)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def since(self, seq: int, limit: int = 200) -> Dict[str, Any]:
        with self._lock:
            events = [e for e in self._history if e["seq"] > seq][:limit]
            return {"events": events, "latest_seq": self._seq,
                    "subscribers": len(self._subscribers)}

    @property
    def latest_seq(self) -> int:
        with self._lock:
            return self._seq


_BUS = EventBus()


def get_bus() -> EventBus:
    return _BUS


def sse_frame(event: Dict[str, Any]) -> bytes:
    """Format one event as a Server-Sent Events frame.

    ``id:`` is set from the sequence number so a browser's automatic reconnect
    sends ``Last-Event-ID`` and the server can resume without duplicates.
    """
    return (
        "id: %d\nevent: %s\ndata: %s\n\n" %
        (event["seq"],
         event["kind"],
         json.dumps(
            event["data"],
            separators=(
                ",",
                ":")))).encode("utf-8")
