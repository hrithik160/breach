import asyncio
import json
import logging
from pathlib import Path
from typing import Set, Dict, Any, List, Optional
from fastapi import WebSocket

from graph_state import GraphState
from resolver import AssetResolver

logger = logging.getLogger("breach_domino.bus")


class EventBus:
    def __init__(
        self,
        state: GraphState,
        resolver: AssetResolver,
        record_path: Optional[Path] = None,
    ):
        self.state = state
        self.resolver = resolver
        self.record_path = record_path
        self.clients: Set[WebSocket] = set()
        self.recorded_events: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)
        await ws.send_json({
            "kind": "snapshot",
            "graph": self.state.snapshot()
        })
        logger.info("Browser WS client connected (%d active)", len(self.clients))

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)
        logger.info("Browser WS client disconnected (%d active)", len(self.clients))

    async def publish(self, event: Dict[str, Any]) -> bool:
        async with self._lock:
            applied = self.state.apply_event(event)
            if not applied:
                logger.debug("Skipped event (target missing or invalid): %s", event)
                return False

            if event.get("type") in ("node_added", "node_updated", "node_removed"):
                self.resolver.rebuild_from_graph(self.state.snapshot())

            # Record live events (Task A7 / Hour 6-8: record a replay of a real event)
            if event.get("source") != "replay":
                self.recorded_events.append(dict(event))
                if self.record_path:
                    try:
                        self.record_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(self.record_path, "a", encoding="utf-8") as f:
                            f.write(json.dumps(event) + "\n")
                    except Exception as exc:
                        logger.warning("Could not record live event: %s", exc)

            msg = {"kind": "event", "event": event}
            await self._broadcast(msg)
            return True

    async def broadcast_snapshot(self) -> None:
        async with self._lock:
            self.resolver.rebuild_from_graph(self.state.snapshot())
            await self._broadcast({
                "kind": "snapshot",
                "graph": self.state.snapshot()
            })

    async def _broadcast(self, message: Dict[str, Any]) -> None:
        stale: Set[WebSocket] = set()
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                stale.add(ws)
        for ws in stale:
            self.clients.discard(ws)