import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("breach_domino.resolver")


class AssetResolver:
    def __init__(self, manual_map_path: Optional[Path] = None):
        self.manual_map_path = manual_map_path
        self._manual_map: Dict[str, str] = {}
        self._dynamic_map: Dict[str, str] = {}
        self._load_manual_map()

    def _load_manual_map(self) -> None:
        if self.manual_map_path and self.manual_map_path.exists():
            try:
                with open(self.manual_map_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    self._manual_map = {str(k).strip().lower(): str(v) for k, v in raw.items()}
                    logger.info("Loaded %d manual asset mappings from %s", len(self._manual_map), self.manual_map_path)
            except Exception as exc:
                logger.warning("Could not read manual_map.json (%s)", exc)

    def rebuild_from_graph(self, graph: Dict[str, Any]) -> None:
        mapping: Dict[str, str] = {}
        for node in graph.get("nodes", []):
            nid = node.get("id")
            if not nid:
                continue
            mapping[nid.lower()] = nid
            if node.get("label"):
                mapping[str(node["label"]).strip().lower()] = nid
            refs = node.get("refs") or {}
            for ref_key in ("ip", "hostname", "cloud_id"):
                val = refs.get(ref_key)
                if val:
                    mapping[str(val).strip().lower()] = nid
        self._dynamic_map = mapping

    def resolve(self, identifier: Optional[str]) -> Optional[str]:
        if not identifier:
            return None
        key = str(identifier).strip().lower()
        node_id = self._dynamic_map.get(key) or self._manual_map.get(key)
        if not node_id:
            logger.warning("Unknown asset identifier '%s' — logged and dropped", identifier)
            return None
        return node_id
