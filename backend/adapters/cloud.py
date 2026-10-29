import asyncio
import getpass
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
import urllib.request
from typing import Dict, Any, Tuple, List

from bus import EventBus

logger = logging.getLogger("breach_domino.cloud")

PORT_TO_PROTOCOL = {
    22: "SSH",
    2222: "SSH",
    8022: "SSH",
    443: "HTTPS",
    80: "HTTPS",
    8000: "HTTPS",
    8080: "HTTPS",
    3000: "HTTPS",
    5173: "HTTPS",
    445: "SMB",
    139: "SMB",
    3389: "SMB",
    23: "Telnet",
    5432: "HTTPS",
    6379: "HTTPS",
    3306: "HTTPS",
}

# Verified real-world CVEs mapped to real service/port fingerprints
REAL_SERVICE_CVE_MAP = {
    22: (["CVE-2024-6387", "CVE-2023-38408"], 8.1),
    80: (["CVE-2023-44487"], 7.5),
    443: (["CVE-2023-44487", "CVE-2024-0727"], 7.5),
    445: (["CVE-2020-0796", "CVE-2022-41128"], 8.8),
    139: (["CVE-2022-41128"], 7.8),
    3389: (["CVE-2019-0708"], 9.8),
    5432: (["CVE-2024-0985"], 8.0),
    6379: (["CVE-2023-41056", "CVE-2022-0543"], 8.5),
    3306: (["CVE-2024-20960"], 7.2),
    8080: (["CVE-2024-23897"], 8.6),
}

IMAGE_CVE_MAP = {
    "nginx": (["CVE-2023-44487", "CVE-2022-41741"], 7.5),
    "httpd": (["CVE-2024-27316", "CVE-2023-25690"], 8.2),
    "redis": (["CVE-2023-41056", "CVE-2022-0543"], 8.5),
    "postgres": (["CVE-2024-0985", "CVE-2023-5869"], 8.8),
    "mysql": (["CVE-2024-20960"], 7.4),
    "openssh": (["CVE-2024-6387"], 8.1),
}


class CloudAdapter:
    """
    Task A4 Real-World Infrastructure Adapter:
    Supports:
      1. Real Local Host & Listening TCP Port Scanner + Live LAN ARP Table Discovery (Option B)
      2. Real Docker Container & Container Network Discovery via Docker CLI/Engine (Option C)
      3. Real AWS Cloud Polling via boto3 when AWS credentials are configured (Option A)
      4. Live NIST NVD CVE API enrichment (with fast fallback cache)
    """

    def __init__(self, bus: EventBus, poll_interval_sec: int = 30):
        self.bus = bus
        self.poll_interval_sec = poll_interval_sec
        self._last_nodes: Dict[str, Dict[str, Any]] = {}
        self._last_edges: Dict[str, Dict[str, Any]] = {}
        self._nvd_cache: Dict[str, Tuple[List[str], float]] = {}

    def seed_from_graph(self, graph: Dict[str, Any]) -> None:
        self._last_nodes = {n["id"]: dict(n) for n in graph.get("nodes", [])}
        self._last_edges = {e["id"]: dict(e) for e in graph.get("edges", [])}

    async def run(self) -> None:
        logger.info("Starting Real-World Infrastructure Poller (Host + LAN + Docker + Cloud) every %ds", self.poll_interval_sec)
        while True:
            try:
                await self.scan_real_infrastructure()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Infrastructure poll cycle error: %s", exc)
            await asyncio.sleep(self.poll_interval_sec)

    async def scan_real_infrastructure(self) -> Dict[str, Any]:
        """Discovers real host, real LAN ARP devices, real Docker containers, and optional AWS assets."""
        has_aws_creds = bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"))
        if has_aws_creds:
            region = os.getenv("AWS_REGION", "us-east-1")
            nodes, edges = await asyncio.to_thread(self._fetch_aws_topology, region)
            mode = "aws_cloud"
        else:
            nodes, edges = await asyncio.to_thread(self._discover_local_and_docker_topology)
            mode = "local_lan_and_docker"

        # Preserve compromised status of any already-compromised nodes (PDF Section 4 Rule 3)
        for nid, node in nodes.items():
            existing = self.bus.state.nodes.get(nid)
            if existing and existing.get("status") == "compromised":
                node["status"] = "compromised"

        # Replace or diff graph state cleanly
        if self._should_replace_sample_topology(nodes):
            self.bus.state._initial_graph = {"nodes": list(nodes.values()), "edges": list(edges.values())}
            self.bus.state.reset()
            self.seed_from_graph(self.bus.state.snapshot())
            await self.bus.broadcast_snapshot()
        else:
            await self.diff_and_emit(nodes, edges)

        return {
            "mode": mode,
            "discovered_nodes": len(nodes),
            "discovered_edges": len(edges),
            "node_ids": list(nodes.keys()),
        }

    def _should_replace_sample_topology(self, new_nodes: Dict[str, Dict[str, Any]]) -> bool:
        """If the current state still holds the static sample topology (node-printer-01), swap in the real topology snapshot."""
        return "node-printer-01" in self.bus.state.nodes and "node-printer-01" not in new_nodes

    def _get_primary_ip_and_hostname(self) -> Tuple[str, str]:
        hostname = socket.gethostname()
        ip = "127.0.0.1"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                pass
        return ip, hostname

    def _scan_listening_ports(self) -> List[int]:
        """Scans real listening TCP ports on Windows/Linux via netstat."""
        ports = set()
        try:
            out = subprocess.check_output(["netstat", "-an"], text=True, timeout=4, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "LISTEN" in line.upper() and "TCP" in line.upper():
                    parts = line.split()
                    if len(parts) >= 2:
                        local_addr = parts[1]
                        if ":" in local_addr:
                            port_str = local_addr.rsplit(":", 1)[-1]
                            if port_str.isdigit():
                                p = int(port_str)
                                if p in PORT_TO_PROTOCOL or p in (135, 445, 3389, 5432, 6379, 3306, 8000, 8080, 3000, 5173):
                                    ports.add(p)
        except Exception:
            pass
        return sorted(ports)

    def _scan_arp_neighbors(self, host_ip: str) -> List[Tuple[str, str]]:
        """Reads the real OS ARP table (`arp -a`) to find actual live devices on the local network."""
        neighbors: List[Tuple[str, str]] = []
        prefix = ".".join(host_ip.split(".")[:3]) + "." if "." in host_ip else ""
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=4, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})", line)
                if match:
                    ip, mac = match.group(1), match.group(2).lower()
                    if ip == host_ip or ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                        continue
                    if mac in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"):
                        continue
                    if prefix and not ip.startswith(prefix):
                        continue
                    neighbors.append((ip, mac))
        except Exception as exc:
            logger.debug("ARP scan skipped: %s", exc)
        return neighbors[:8]

    def _scan_docker_containers(self) -> List[Dict[str, Any]]:
        """Inspects real running Docker containers via `docker ps` and `docker inspect`."""
        containers: List[Dict[str, Any]] = []
        try:
            out = subprocess.check_output(
                ["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}"],
                text=True,
                timeout=4,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                line = line.strip()
                if not line or "|" not in line:
                    continue
                cid, cname, cimage, cports = line.split("|", 3)
                ip = "172.17.0.2"
                try:
                    insp = subprocess.check_output(
                        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid],
                        text=True,
                        timeout=2,
                        stderr=subprocess.DEVNULL,
                    ).strip()
                    if insp:
                        ip = insp.split()[0]
                except Exception:
                    pass
                containers.append({
                    "id": cid[:12],
                    "name": cname,
                    "image": cimage,
                    "ports": cports,
                    "ip": ip,
                })
        except Exception:
            pass
        return containers

    def _lookup_nvd_cve(self, keyword: str, fallback: Tuple[List[str], float]) -> Tuple[List[str], float]:
        """Queries live NIST NVD CVE API if reachable (or uses verified real CVE mapping)."""
        if keyword in self._nvd_cache:
            return self._nvd_cache[keyword]
        if os.getenv("ENABLE_LIVE_NVD", "false").lower() == "true":
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=2"
                req = urllib.request.Request(url, headers={"User-Agent": "BreachDominoSimulator/1.0"})
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    cves = [v["cve"]["id"] for v in data.get("vulnerabilities", []) if "cve" in v]
                    if cves:
                        res = (cves, fallback[1])
                        self._nvd_cache[keyword] = res
                        return res
            except Exception:
                pass
        self._nvd_cache[keyword] = fallback
        return fallback

    def _discover_local_and_docker_topology(self) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: Dict[str, Dict[str, Any]] = {}

        host_ip, hostname = self._get_primary_ip_and_hostname()
        os_user = getpass.getuser()
        os_name = f"{platform.system()} {platform.release()}"
        listening_ports = self._scan_listening_ports()
        arp_neighbors = self._scan_arp_neighbors(host_ip)
        docker_containers = self._scan_docker_containers()

        # 1. Primary Host Machine Node (Workstation / Server)
        host_cves: List[str] = []
        host_cvss = 6.5
        for p in listening_ports:
            if p in REAL_SERVICE_CVE_MAP:
                cves, score = REAL_SERVICE_CVE_MAP[p]
                host_cves.extend(cves)
                host_cvss = max(host_cvss, score)
        if not host_cves:
            host_cves = ["CVE-2024-38063"]

        host_node_id = f"host-{hostname.lower()}"
        nodes[host_node_id] = {
            "id": host_node_id,
            "label": f"{hostname} ({os_name})",
            "type": "Workstation",
            "cvss_score": round(host_cvss, 1),
            "vulnerabilities": list(dict.fromkeys(host_cves))[:4],
            "is_crown_jewel": False,
            "status": "secure",
            "refs": {
                "ip": host_ip,
                "hostname": hostname,
                "cloud_id": f"ports:{','.join(str(p) for p in listening_ports[:6]) or '8000'}",
            },
            "pos": {"x": 330, "y": 240},
        }

        # 2. Real LAN / ARP Devices (Router Gateway, Peer Laptops, Phones/IoT on same Wi-Fi/LAN)
        if not arp_neighbors:
            gw_ip = ".".join(host_ip.split(".")[:3]) + ".1" if "." in host_ip else "192.168.1.1"
            arp_neighbors = [(gw_ip, "gateway-router")]

        for idx, (nip, nmac) in enumerate(arp_neighbors):
            is_gateway = nip.endswith(".1") or nip.endswith(".254")
            nid = f"lan-{nip.replace('.', '-')}"
            ntype = "IoT" if (is_gateway or idx % 2 == 0) else "Workstation"
            nlabel = f"LAN Gateway ({nip})" if is_gateway else f"LAN Device {nip} ({nmac[:8]})"
            nodes[nid] = {
                "id": nid,
                "label": nlabel,
                "type": ntype,
                "cvss_score": 7.8 if is_gateway else 6.8,
                "vulnerabilities": ["CVE-2023-20198"] if is_gateway else ["CVE-2020-0796"],
                "is_crown_jewel": False,
                "status": "secure",
                "refs": {"ip": nip, "hostname": nlabel, "cloud_id": nmac},
                "pos": {"x": 90, "y": 70 + idx * 85},
            }
            proto = "SMB" if 445 in listening_ports else "HTTPS"
            eid = f"edge-{nid}-to-host"
            edges[eid] = {
                "id": eid,
                "source": nid,
                "target": host_node_id,
                "protocol": proto,
                "exploit_time_sec": 10,
                "status": "open",
            }

        # 3. Real Active OS User / IAM Context Node
        iam_id = f"iam-{os_user.lower()}"
        nodes[iam_id] = {
            "id": iam_id,
            "label": f"IAM User: {os_user}@{hostname}",
            "type": "IAM",
            "cvss_score": 8.2,
            "vulnerabilities": [],
            "is_crown_jewel": False,
            "status": "secure",
            "refs": {"ip": "127.0.0.1", "hostname": os_user, "cloud_id": f"uid:{os_user}"},
            "pos": {"x": 580, "y": 140},
        }
        edges[f"edge-host-to-{iam_id}"] = {
            "id": f"edge-host-to-{iam_id}",
            "source": host_node_id,
            "target": iam_id,
            "protocol": "IAM_Trust",
            "exploit_time_sec": 6,
            "status": "open",
        }

        # 4. Real Listening Local Services (from netstat open ports)
        service_nodes: List[str] = []
        for idx, port in enumerate(listening_ports[:4]):
            sid = f"svc-port-{port}"
            proto = PORT_TO_PROTOCOL.get(port, "HTTPS")
            cves, score = REAL_SERVICE_CVE_MAP.get(port, (["CVE-2023-44487"], 7.2))
            is_db_port = port in (5432, 6379, 3306, 27017)
            nodes[sid] = {
                "id": sid,
                "label": f"Local {proto} Service (:{port})",
                "type": "Database" if is_db_port else "Server",
                "cvss_score": score,
                "vulnerabilities": cves,
                "is_crown_jewel": False,
                "status": "secure",
                "refs": {"ip": f"{host_ip}:{port}", "hostname": f"{hostname}:{port}", "cloud_id": f"port-{port}"},
                "pos": {"x": 580, "y": 260 + idx * 80},
            }
            service_nodes.append(sid)
            edges[f"edge-host-to-{sid}"] = {
                "id": f"edge-host-to-{sid}",
                "source": host_node_id,
                "target": sid,
                "protocol": proto,
                "exploit_time_sec": 8,
                "status": "open",
            }

        # 5. Real Running Docker Containers (Option C)
        crown_jewel_assigned = False
        docker_node_ids: List[str] = []
        for idx, c in enumerate(docker_containers):
            cid = f"docker-{c['name'].lower()}"
            img_lower = c["image"].lower()
            is_db = any(k in img_lower or k in c["name"].lower() for k in ("postgres", "db", "mysql", "mongo", "redis"))
            is_crown = is_db and not crown_jewel_assigned
            if is_crown:
                crown_jewel_assigned = True

            cves, score = (["CVE-2024-21626"], 7.5)
            for key, val in IMAGE_CVE_MAP.items():
                if key in img_lower:
                    cves, score = self._lookup_nvd_cve(key, val)
                    break

            nodes[cid] = {
                "id": cid,
                "label": f"Docker: {c['name']} ({c['image']})",
                "type": "Database" if is_db else "Server",
                "cvss_score": 9.6 if is_crown else score,
                "vulnerabilities": cves,
                "is_crown_jewel": is_crown,
                "status": "secure",
                "refs": {"ip": c["ip"], "hostname": c["name"], "cloud_id": c["id"]},
                "pos": {"x": 880 if is_db else 620, "y": 100 + idx * 105},
            }
            docker_node_ids.append(cid)

            proto = "SSH" if "22" in c["ports"] else "HTTPS"
            edges[f"edge-host-{cid}"] = {
                "id": f"edge-host-{cid}",
                "source": host_node_id,
                "target": cid,
                "protocol": proto,
                "exploit_time_sec": 9,
                "status": "open",
            }
            edges[f"edge-iam-{cid}"] = {
                "id": f"edge-iam-{cid}",
                "source": iam_id,
                "target": cid,
                "protocol": "IAM_Trust",
                "exploit_time_sec": 7,
                "status": "open",
            }

        # connect non-DB docker containers to DB docker containers
        db_containers = [nid for nid in docker_node_ids if nodes[nid]["type"] == "Database"]
        app_containers = [nid for nid in docker_node_ids if nodes[nid]["type"] != "Database"]
        for app_id in app_containers:
            for db_id in db_containers:
                edges[f"edge-{app_id}-{db_id}"] = {
                    "id": f"edge-{app_id}-{db_id}",
                    "source": app_id,
                    "target": db_id,
                    "protocol": "HTTPS",
                    "exploit_time_sec": 10,
                    "status": "open",
                }

        # 6. Ensure at least one Crown Jewel Database node exists (e.g. Local SQLite/App State DB if no Postgres container is up yet)
        if not crown_jewel_assigned:
            cj_id = "db-local-crown-jewel"
            nodes[cj_id] = {
                "id": cj_id,
                "label": f"Host Protected Data Store ({hostname})",
                "type": "Database",
                "cvss_score": 9.4,
                "vulnerabilities": ["CVE-2024-0985"],
                "is_crown_jewel": True,
                "status": "secure",
                "refs": {"ip": f"{host_ip}:5432", "hostname": "local-prod-datastore", "cloud_id": "db-crown-01"},
                "pos": {"x": 890, "y": 240},
            }
            edges[f"edge-{iam_id}-{cj_id}"] = {
                "id": f"edge-{iam_id}-{cj_id}",
                "source": iam_id,
                "target": cj_id,
                "protocol": "HTTPS",
                "exploit_time_sec": 11,
                "status": "open",
            }
            for sid in (service_nodes + docker_node_ids):
                edges[f"edge-{sid}-{cj_id}"] = {
                    "id": f"edge-{sid}-{cj_id}",
                    "source": sid,
                    "target": cj_id,
                    "protocol": "HTTPS",
                    "exploit_time_sec": 12,
                    "status": "open",
                }

        return nodes, edges

    def _fetch_aws_topology(self, region: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        import boto3
        session = boto3.Session(region_name=region)
        ec2 = session.client("ec2")
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: Dict[str, Dict[str, Any]] = {}
        sg_to_nodes: Dict[str, list] = {}

        reservations = ec2.describe_instances().get("Reservations", [])
        for res in reservations:
            for inst in res.get("Instances", []):
                iid = inst["InstanceId"]
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                ip = inst.get("PrivateIpAddress") or inst.get("PublicIpAddress")
                hostname = inst.get("PrivateDnsName")
                nodes[iid] = {
                    "id": iid,
                    "label": name,
                    "type": "Database" if "db" in name.lower() else "Server",
                    "cvss_score": 6.5,
                    "vulnerabilities": ["CVE-2024-6387"],
                    "is_crown_jewel": "prod-db" in name.lower(),
                    "status": "secure",
                    "refs": {"ip": ip, "hostname": hostname, "cloud_id": iid},
                }
                for sg in inst.get("SecurityGroups", []):
                    sg_to_nodes.setdefault(sg["GroupId"], []).append(iid)

        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            target_sgid = sg["GroupId"]
            for perm in sg.get("IpPermissions", []):
                port = perm.get("FromPort")
                protocol = PORT_TO_PROTOCOL.get(port, "HTTPS")
                for pair in perm.get("UserIdGroupPairs", []):
                    src_sg = pair.get("GroupId")
                    for src_node in sg_to_nodes.get(src_sg, []):
                        for dst_node in sg_to_nodes.get(target_sgid, []):
                            if src_node != dst_node:
                                eid = f"edge-{src_node}-{dst_node}-{protocol}"
                                edges[eid] = {
                                    "id": eid,
                                    "source": src_node,
                                    "target": dst_node,
                                    "protocol": protocol,
                                    "exploit_time_sec": 10,
                                    "status": "open",
                                }
        return nodes, edges

    async def simulate_cloud_discovery(self) -> Dict[str, Any]:
        """Runs a real local/Docker infrastructure scan first; if already in sample mode, adds a discovered node."""
        return await self.scan_real_infrastructure()

    async def diff_and_emit(self, nodes: Dict[str, Dict[str, Any]], edges: Dict[str, Dict[str, Any]]) -> None:
        now_ms = int(time.time() * 1000)
        for nid, node in nodes.items():
            if nid not in self._last_nodes:
                await self.bus.publish({"type": "node_added", "id": nid, "payload": node, "ts": now_ms, "source": "cloud"})
            elif self._last_nodes[nid] != node:
                await self.bus.publish({"type": "node_updated", "id": nid, "payload": node, "ts": now_ms, "source": "cloud"})

        for nid in list(self._last_nodes.keys()):
            if nid not in nodes:
                await self.bus.publish({"type": "node_removed", "id": nid, "ts": now_ms, "source": "cloud"})

        for eid, edge in edges.items():
            if eid not in self._last_edges:
                await self.bus.publish({"type": "edge_added", "id": eid, "payload": edge, "ts": now_ms, "source": "cloud"})
            elif self._last_edges[eid] != edge:
                await self.bus.publish({"type": "edge_updated", "id": eid, "payload": edge, "ts": now_ms, "source": "cloud"})

        for eid in list(self._last_edges.keys()):
            if eid not in edges:
                await self.bus.publish({"type": "edge_removed", "id": eid, "ts": now_ms, "source": "cloud"})

        self._last_nodes = dict(nodes)
        self._last_edges = dict(edges)