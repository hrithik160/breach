import asyncio
import json
import logging
import os
import time
from typing import Dict, Any, Optional

from bus import EventBus
from resolver import AssetResolver

logger = logging.getLogger("breach_domino.ws_source")


class WebSocketSourceAdapter:
    def __init__(self, bus: EventBus, resolver: AssetResolver, upstream_url: Optional[str] = None):
        self.bus = bus
        self.resolver = resolver
        self.upstream_url = upstream_url or os.getenv("UPSTREAM_WS_URL", "ws://localhost:8000/upstream/ws")

    async def run(self) -> None:
        if not self.upstream_url:
            logger.info("UPSTREAM_WS_URL not set; WebSocketSourceAdapter idle")
            return

        try:
            import websockets
        except ImportError:
            logger.warning("websockets package not installed; WebSocketSourceAdapter idle")
            return

        backoff = 1.0
        max_backoff = 30.0

        while True:
            try:
                logger.info("Connecting to upstream WebSocket stream: %s", self.upstream_url)
                async with websockets.connect(self.upstream_url) as ws:
                    backoff = 1.0
                    async for raw_msg in ws:
                        event = self.normalize_message(raw_msg)
                        if event:
                            await self.bus.publish(event)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Upstream WS disconnected (%s). Reconnecting in %.1fs...", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, max_backoff)

    def normalize_message(self, raw_msg: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(raw_msg)
        except Exception:
            logger.warning("Invalid JSON from upstream WS: %s", raw_msg)
            return None

        now_ms = int(data.get("ts") or time.time() * 1000)

        if "type" in data and "id" in data:
            resolved_id = self.resolver.resolve(data["id"]) or data["id"]
            return {
                "type": data["type"],
                "id": resolved_id,
                "payload": data.get("payload", {}),
                "ts": now_ms,
                "source": "ws",
            }

        src = data.get("src") or data.get("src_host") or data.get("src_ip")
        dst = data.get("dst") or data.get("dst_host") or data.get("dst_ip")
        if src and dst:
            src_id = self.resolver.resolve(src)
            dst_id = self.resolver.resolve(dst)
            if src_id and dst_id:
                for eid, edge in self.bus.state.edges.items():
                    if edge.get("source") == src_id and edge.get("target") == dst_id:
                        return {
                            "type": "edge_active_attack",
                            "id": eid,
                            "payload": {"status": "active_attack"},
                            "ts": now_ms,
                            "source": "ws",
                        }

        host = data.get("host") or data.get("ip") or data.get("asset_id") or dst or src
        node_id = self.resolver.resolve(host)
        if not node_id:
            return None

        event_type = data.get("event_type", "node_compromised")
        payload = data.get("payload")
        if not payload:
            if event_type == "cve_found":
                payload = {
                    "vulnerabilities": data.get("vulnerabilities", ["CVE-2024-9999"]),
                    "cvss_score": float(data.get("cvss_score", 8.5)),
                }
            else:
                payload = {"status": "compromised"}

        return {
            "type": event_type,
            "id": node_id,
            "payload": payload,
            "ts": now_ms,
            "source": "ws",
        }