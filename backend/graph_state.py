import copy
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("breach_domino.graph_state")


class GraphState:
    def __init__(self, topology_path: Optional[Path] = None):
        self.topology_path = topology_path
        self._initial_graph = self._load_initial_topology()
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.reset()

    def _load_initial_topology(self) -> Dict[str, Any]:
        if self.topology_path and self.topology_path.exists():
            try:
                with open(self.topology_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info(
                        "Loaded topology from %s (%d nodes, %d edges)",
                        self.topology_path,
                        len(data.get("nodes", [])),
                        len(data.get("edges", [])),
                    )
                    return data
            except Exception as exc:
                logger.warning("Failed to load %s (%s)", self.topology_path, exc)
        return {"nodes": [], "edges": []}

    def reset(self) -> None:
        fresh = copy.deepcopy(self._initial_graph)
        self.nodes = {n["id"]: n for n in fresh.get("nodes", [])}
        self.edges = {e["id"]: e for e in fresh.get("edges", [])}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
        }

    def apply_event(self, event: Dict[str, Any]) -> bool:
        etype = event.get("type")
        target_id = event.get("id")
        payload = event.get("payload") or {}

        if not etype or not target_id:
            logger.warning("Invalid GraphEvent missing type or id: %s", event)
            return False

        if etype == "node_added":
            self.nodes[target_id] = {"id": target_id, **payload}
            return True
        elif etype == "node_removed":
            if target_id not in self.nodes:
                return False
            self.nodes.pop(target_id, None)
            return True
        elif etype == "node_updated":
            if target_id not in self.nodes:
                return False
            self.nodes[target_id].update(payload)
            return True
        elif etype == "node_compromised":
            if target_id not in self.nodes:
                return False
            self.nodes[target_id]["status"] = "compromised"
            self.nodes[target_id].update(payload)
            return True
        elif etype == "cve_found":
            if target_id not in self.nodes:
                return False
            node = self.nodes[target_id]
            new_cves = payload.get("vulnerabilities", [])
            merged = list(dict.fromkeys(node.get("vulnerabilities", []) + new_cves))
            node["vulnerabilities"] = merged
            if "cvss_score" in payload:
                node["cvss_score"] = payload["cvss_score"]
            return True
        elif etype == "edge_added":
            self.edges[target_id] = {"id": target_id, **payload}
            return True
        elif etype == "edge_removed":
            if target_id not in self.edges:
                return False
            self.edges.pop(target_id, None)
            return True
        elif etype == "edge_updated":
            if target_id not in self.edges:
                return False
            self.edges[target_id].update(payload)
            return True
        elif etype == "edge_active_attack":
            if target_id not in self.edges:
                return False
            self.edges[target_id]["status"] = "active_attack"
            self.edges[target_id].update(payload)
            return True

        logger.warning("Unhandled GraphEvent type: %s", etype)
        return False
