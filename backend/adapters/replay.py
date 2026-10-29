import asyncio
import json
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from bus import EventBus

logger = logging.getLogger("breach_domino.replay")


class ReplayAdapter:
    """
    Task A2 Replay Adapter & Autonomous Red-Team Chaos Engine:
    1. Replays static /shared/sample_events.jsonl when running on the sample topology (matching Person B's node-printer -> node-prod-crown-jewel).
    2. Dynamically synthesizes a Dijkstra/BFS attack path when running on real-world scanned topology (Options B + C)
       or when a custom entry node is clicked.
    3. Handles start / pause / reset and speed multipliers over /ws via { kind: 'replay_control' }.
    """

    def __init__(self, bus: EventBus, events_path: Path):
        self.bus = bus
        self.events_path = events_path
        self.speed: float = 1.0
        self._running: bool = False
        self._paused: bool = False
        self._index: int = 0
        self._task: Optional[asyncio.Task] = None
        self._static_events: List[Dict[str, Any]] = self._load_events()
        self._active_events: List[Dict[str, Any]] = []

    def _load_events(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if not self.events_path.exists():
            logger.warning("Replay file %s not found", self.events_path)
            return events
        with open(self.events_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        logger.info("Loaded %d replay events from %s", len(events), self.events_path)
        return events

    def _build_dynamic_attack_chain(self, entry_id: Optional[str] = None) -> List[Dict[str, Any]]:
        nodes = self.bus.state.nodes
        edges = self.bus.state.edges

        if not nodes:
            return []

        crown_jewel = next((n for n in nodes.values() if n.get("is_crown_jewel")), None)
        if not crown_jewel:
            crown_jewel = next((n for n in nodes.values() if n.get("type") == "Database"), list(nodes.values())[-1])
        target_id = crown_jewel["id"]

        if not entry_id or entry_id not in nodes:
            entry = next(
                (n for n in nodes.values() if n.get("type") in ("IoT", "Workstation") and n["id"] != target_id),
                None,
            )
            if not entry:
                entry = list(nodes.values())[0]
            entry_id = entry["id"]

        adj: Dict[str, List[Tuple[str, str]]] = {}
        for eid, e in edges.items():
            if e.get("status") == "firewalled":
                continue
            s, d = e.get("source"), e.get("target")
            if s and d:
                adj.setdefault(s, []).append((d, eid))
                adj.setdefault(d, []).append((s, eid))

        queue = [(entry_id, [entry_id], [])]
        visited = {entry_id}
        path_nodes: List[str] = [entry_id]
        path_edges: List[str] = []

        while queue:
            curr, n_path, e_path = queue.pop(0)
            if curr == target_id:
                path_nodes = n_path
                path_edges = e_path
                break
            for neighbor, edge_id in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, n_path + [neighbor], e_path + [edge_id]))

        if len(path_nodes) == 1 and len(nodes) > 1:
            all_other = [nid for nid in nodes.keys() if nid != entry_id and nid != target_id]
            path_nodes = [entry_id] + all_other[:3] + [target_id]
            path_edges = []
            for i in range(len(path_nodes) - 1):
                s, d = path_nodes[i], path_nodes[i + 1]
                match_e = next(
                    (
                        eid
                        for eid, e in edges.items()
                        if (e.get("source") == s and e.get("target") == d)
                        or (e.get("source") == d and e.get("target") == s)
                    ),
                    None,
                )
                if match_e:
                    path_edges.append(match_e)

        events: List[Dict[str, Any]] = []
        now = int(time.time() * 1000)

        events.append({
            "ts": now,
            "type": "node_compromised",
            "id": path_nodes[0],
            "payload": {"status": "compromised"},
            "source": "replay",
        })

        t_offset = 1200
        for i in range(len(path_nodes) - 1):
            next_node = path_nodes[i + 1]
            via_edge = path_edges[i] if i < len(path_edges) else None

            if via_edge and via_edge in edges:
                events.append({
                    "ts": now + t_offset,
                    "type": "edge_active_attack",
                    "id": via_edge,
                    "payload": {"status": "active_attack"},
                    "source": "replay",
                })
                t_offset += 1200

            events.append({
                "ts": now + t_offset,
                "type": "node_compromised",
                "id": next_node,
                "payload": {"status": "compromised"},
                "source": "replay",
            })
            t_offset += 1200

        logger.info("Generated dynamic attack chain across %d nodes: %s", len(path_nodes), " -> ".join(path_nodes))
        return events

    def _prepare_events(self, entry_id: Optional[str] = None) -> List[Dict[str, Any]]:
        nodes = self.bus.state.nodes
        first_static_id = self._static_events[0]["id"] if self._static_events else ""
        if first_static_id in nodes and (not entry_id or entry_id == first_static_id):
            return list(self._static_events)
        return self._build_dynamic_attack_chain(entry_id)

    async def handle_control(self, msg: Dict[str, Any], entry_id: Optional[str] = None) -> None:
        action = msg.get("action")
        if "speed" in msg and msg["speed"]:
            self.speed = max(float(msg["speed"]), 0.1)

        if action == "start":
            self._paused = False
            if self._task and not self._task.done():
                self._task.cancel()
            # Clear previous compromised/active_attack state so the wave animates cleanly from step 0
            for node in self.bus.state.nodes.values():
                node["status"] = "secure"
            for edge in self.bus.state.edges.values():
                edge["status"] = "open"
            await self.bus.broadcast_snapshot()
            await asyncio.sleep(0.08)
            self._active_events = self._prepare_events(entry_id)
            self._index = 0
            self._running = True
            self._task = asyncio.create_task(self._run_loop())
        elif action == "pause":
            self._paused = True
        elif action == "reset":
            self._paused = True
            self._running = False
            if self._task and not self._task.done():
                self._task.cancel()
            self._index = 0
            for node in self.bus.state.nodes.values():
                node["status"] = "secure"
            for edge in self.bus.state.edges.values():
                edge["status"] = "open"
            await self.bus.broadcast_snapshot()

    async def _run_loop(self) -> None:
        try:
            while self._running and self._index < len(self._active_events):
                if self._paused:
                    await asyncio.sleep(0.05)
                    continue

                current_event = dict(self._active_events[self._index])
                current_event["ts"] = int(time.time() * 1000)
                current_event["source"] = "replay"
                await self.bus.publish(current_event)

                next_idx = self._index + 1
                if next_idx < len(self._active_events):
                    t_curr = self._active_events[self._index].get("ts", 0)
                    t_next = self._active_events[next_idx].get("ts", t_curr + 1200)
                    delta_sec = max((t_next - t_curr) / 1000.0, 0.05) / self.speed
                    await asyncio.sleep(delta_sec)

                self._index = next_idx
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False