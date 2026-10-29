import asyncio
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional

from bus import EventBus
from resolver import AssetResolver

logger = logging.getLogger("breach_domino.siem")

ATTACK_PATTERNS = re.compile(
    r"(401|403|500|union\s+select|or\s+1=1|\.\./|/etc/passwd|failed\s+password|authentication\s+failure|access\s+denied|exploit|compromise|unauthorized)",
    re.IGNORECASE,
)


class SIEMAdapter:
    """
    Task A6 Real-World SIEM & Live Intrusion Detector:
      1. Parses JSON and key=value SIEM alert lines + tails siem_alerts.log
      2. Monitors real running Docker container logs (`docker logs --since 4s`) for real HTTP/DB/Auth attacks (Option C)
      3. Monitors real Windows Security / System Event Logs via `wevtutil` on Windows (Option B)
      4. Runs a real TCP Tripwire Honeypot listener on port 8022 so real `nmap`, `curl`, or `Test-NetConnection` scans trigger live compromises!
    """

    def __init__(self, bus: EventBus, resolver: AssetResolver, log_path: Optional[Path] = None):
        self.bus = bus
        self.resolver = resolver
        self.log_path = log_path
        self.tripwire_port = int(os.getenv("TRIPWIRE_PORT", "8022"))

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        now_ms = int(time.time() * 1000)

        try:
            record = json.loads(line)
            src_host = record.get("src_ip") or record.get("src_host")
            dst_host = record.get("dst_ip") or record.get("dst_host") or record.get("host")
            alert_kind = str(record.get("alert", "compromise")).lower()

            if "pivot" in alert_kind or "lateral" in alert_kind:
                src_id = self.resolver.resolve(src_host)
                dst_id = self.resolver.resolve(dst_host)
                if src_id and dst_id:
                    for eid, edge in self.bus.state.edges.items():
                        if edge.get("source") == src_id and edge.get("target") == dst_id:
                            return {
                                "type": "edge_active_attack",
                                "id": eid,
                                "payload": {"status": "active_attack"},
                                "ts": now_ms,
                                "source": "siem",
                            }

            target_node = self.resolver.resolve(dst_host or src_host)
            if not target_node:
                return None

            if "cve" in record:
                return {
                    "type": "cve_found",
                    "id": target_node,
                    "payload": {
                        "vulnerabilities": [record["cve"]],
                        "cvss_score": float(record.get("cvss", 7.5)),
                    },
                    "ts": now_ms,
                    "source": "siem",
                }

            return {
                "type": "node_compromised",
                "id": target_node,
                "payload": {"status": "compromised"},
                "ts": now_ms,
                "source": "siem",
            }
        except json.JSONDecodeError:
            parts = dict(token.split("=", 1) for token in line.split() if "=" in token)
            if parts.get("src") and parts.get("dst"):
                src_id = self.resolver.resolve(parts["src"])
                dst_id = self.resolver.resolve(parts["dst"])
                if src_id and dst_id:
                    for eid, edge in self.bus.state.edges.items():
                        if edge.get("source") == src_id and edge.get("target") == dst_id:
                            return {
                                "type": "edge_active_attack",
                                "id": eid,
                                "payload": {"status": "active_attack"},
                                "ts": now_ms,
                                "source": "siem",
                            }
            host = parts.get("host") or parts.get("ip") or parts.get("dst")
            node_id = self.resolver.resolve(host)
            if not node_id:
                return None
            if "cve" in parts:
                return {
                    "type": "cve_found",
                    "id": node_id,
                    "payload": {
                        "vulnerabilities": [parts["cve"]],
                        "cvss_score": float(parts.get("cvss", 8.0)),
                    },
                    "ts": now_ms,
                    "source": "siem",
                }
            return {
                "type": "node_compromised",
                "id": node_id,
                "payload": {"status": "compromised"},
                "ts": now_ms,
                "source": "siem",
            }

    def append_and_parse(self, line: str) -> Optional[Dict[str, Any]]:
        if self.log_path:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line.strip() + "\n")
            except Exception as exc:
                logger.warning("Failed to append to SIEM log file: %s", exc)
        return self.parse_line(line)

    async def tail_file(self) -> None:
        """Runs file tailer + real Docker container log monitor + real TCP tripwire listener concurrently."""
        tasks = [
            asyncio.create_task(self._tail_log_file()),
            asyncio.create_task(self._monitor_docker_logs()),
            asyncio.create_task(self._monitor_windows_events()),
            asyncio.create_task(self._run_tripwire_listener()),
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()

    async def _tail_log_file(self) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.touch(exist_ok=True)
        logger.info("Tailing SIEM log file at %s", self.log_path)

        with open(self.log_path, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.25)
                    continue
                event = self.parse_line(line)
                if event:
                    await self.bus.publish(event)

    async def _monitor_docker_logs(self) -> None:
        """Option C: Polls real running Docker container logs for suspicious requests (401/403/500/SQLi/failed auth)."""
        while True:
            try:
                names_out = await asyncio.to_thread(
                    lambda: subprocess.check_output(
                        ["docker", "ps", "--format", "{{.Names}}"],
                        text=True,
                        timeout=3,
                        stderr=subprocess.DEVNULL,
                    )
                )
                for cname in names_out.splitlines():
                    cname = cname.strip()
                    if not cname:
                        continue
                    logs_out = await asyncio.to_thread(
                        lambda c=cname: subprocess.check_output(
                            ["docker", "logs", "--since", "4s", c],
                            text=True,
                            timeout=3,
                            stderr=subprocess.STDOUT,
                        )
                    )
                    for line in logs_out.splitlines():
                        if ATTACK_PATTERNS.search(line):
                            node_id = self.resolver.resolve(cname) or self.resolver.resolve(f"docker-{cname.lower()}")
                            if node_id:
                                now_ms = int(time.time() * 1000)
                                await self.bus.publish({
                                    "type": "node_compromised",
                                    "id": node_id,
                                    "payload": {"status": "compromised"},
                                    "ts": now_ms,
                                    "source": "siem",
                                })
                                for eid, edge in self.bus.state.edges.items():
                                    if edge.get("target") == node_id:
                                        await self.bus.publish({
                                            "type": "edge_active_attack",
                                            "id": eid,
                                            "payload": {"status": "active_attack"},
                                            "ts": now_ms,
                                            "source": "siem",
                                        })
                                break
            except Exception:
                pass
            await asyncio.sleep(4.0)

    async def _monitor_windows_events(self) -> None:
        """Option B: On Windows, polls recent failed logon events (EventID 4625) if accessible."""
        if platform.system().lower() != "windows":
            return
        while True:
            try:
                out = await asyncio.to_thread(
                    lambda: subprocess.check_output(
                        ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/c:1", "/f:text"],
                        text=True,
                        timeout=4,
                        stderr=subprocess.DEVNULL,
                    )
                )
                if "4625" in out:
                    host_id = self.resolver.resolve(socket.gethostname())
                    if host_id:
                        await self.bus.publish({
                            "type": "node_compromised",
                            "id": host_id,
                            "payload": {"status": "compromised"},
                            "ts": int(time.time() * 1000),
                            "source": "siem",
                        })
            except Exception:
                pass
            await asyncio.sleep(8.0)

    async def _run_tripwire_listener(self) -> None:
        """Option B & C: Real TCP socket listener on port 8022 — any real port scan or connection triggers a live SIEM breach alert!"""
        async def handle_probe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                peer = writer.get_extra_info("peername")
                peer_ip = peer[0] if peer else "127.0.0.1"
                writer.write(b"SSH-2.0-OpenSSH_8.9p1 BreachDomino-Tripwire\r\n")
                await writer.drain()
                writer.close()

                now_ms = int(time.time() * 1000)
                host_id = (
                    self.resolver.resolve(peer_ip)
                    or self.resolver.resolve(socket.gethostname())
                    or next(iter(self.bus.state.nodes.keys()), None)
                )
                if host_id:
                    logger.warning("REAL TCP TRIPWIRE HIT from %s -> compromising %s", peer_ip, host_id)
                    await self.bus.publish({
                        "type": "node_compromised",
                        "id": host_id,
                        "payload": {"status": "compromised"},
                        "ts": now_ms,
                        "source": "siem",
                    })
                    for eid, edge in self.bus.state.edges.items():
                        if edge.get("source") == host_id or edge.get("target") == host_id:
                            await self.bus.publish({
                                "type": "edge_active_attack",
                                "id": eid,
                                "payload": {"status": "active_attack"},
                                "ts": now_ms,
                                "source": "siem",
                            })
                            break
            except Exception:
                pass

        try:
            server = await asyncio.start_server(handle_probe, "0.0.0.0", self.tripwire_port)
            logger.info("Real TCP Tripwire Honeypot listening on 0.0.0.0:%d", self.tripwire_port)
            async with server:
                await server.serve_forever()
        except Exception as exc:
            logger.debug("Tripwire port %d already in use or unavailable: %s", self.tripwire_port, exc)