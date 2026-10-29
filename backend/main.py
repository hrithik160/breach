import asyncio
import copy
import json
import logging
import os
import socket
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any, Set, Optional, List

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from bus import EventBus
from graph_state import GraphState
from resolver import AssetResolver
from adapters.replay import ReplayAdapter
from adapters.cloud import CloudAdapter
from adapters.ws_source import WebSocketSourceAdapter
from adapters.siem import SIEMAdapter
from adapters.website_scanner import WebsiteScanner

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("breach_domino.main")

BASE_DIR = Path(__file__).resolve().parent
SHARED_DIR = BASE_DIR.parent / "shared"
if not (SHARED_DIR / "topology.sample.json").exists() and (BASE_DIR / "shared" / "topology.sample.json").exists():
    SHARED_DIR = BASE_DIR / "shared"

TEST_SITE_DIR = BASE_DIR.parent / "test_site"
if not (TEST_SITE_DIR / "index.html").exists() and (BASE_DIR / "test_site" / "index.html").exists():
    TEST_SITE_DIR = BASE_DIR / "test_site"

FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"

SOURCE_MODE = os.getenv("SOURCE", "replay").lower()

state = GraphState(topology_path=SHARED_DIR / "topology.sample.json")
resolver = AssetResolver(manual_map_path=SHARED_DIR / "manual_map.json")
resolver.rebuild_from_graph(state.snapshot())

bus = EventBus(
    state=state,
    resolver=resolver,
    record_path=SHARED_DIR / "recorded_events.jsonl",
)
replay_adapter = ReplayAdapter(bus=bus, events_path=SHARED_DIR / "sample_events.jsonl")
cloud_adapter = CloudAdapter(bus=bus, poll_interval_sec=int(os.getenv("CLOUD_POLL_SEC", "30")))
cloud_adapter.seed_from_graph(state.snapshot())
ws_source_adapter = WebSocketSourceAdapter(bus=bus, resolver=resolver)
siem_adapter = SIEMAdapter(
    bus=bus,
    resolver=resolver,
    log_path=Path(os.getenv("SIEM_LOG_PATH", str(BASE_DIR / "siem_alerts.log"))),
)
website_scanner = WebsiteScanner(test_site_dir=TEST_SITE_DIR)

upstream_subscribers: Set[WebSocket] = set()
live_tasks: list[asyncio.Task] = []


def start_live_background_tasks() -> None:
    global live_tasks
    stop_live_background_tasks()
    live_tasks = [
        asyncio.create_task(cloud_adapter.run()),
        asyncio.create_task(ws_source_adapter.run()),
        asyncio.create_task(siem_adapter.tail_file()),
    ]


def stop_live_background_tasks() -> None:
    global live_tasks
    for t in live_tasks:
        if not t.done():
            t.cancel()
    live_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Breach Domino Backend in SOURCE=%s mode", SOURCE_MODE)
    if SOURCE_MODE == "live":
        start_live_background_tasks()
    yield
    stop_live_background_tasks()


app = FastAPI(title="Breach Domino Simulator Backend (Wiz Security Graph + Chaos Engine)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if TEST_SITE_DIR.exists():
    app.mount("/site", StaticFiles(directory=str(TEST_SITE_DIR), html=True), name="test_site")


# ============================================================================
# Wiz Feature Recreation & Optimal Choke-Point Engine (Backend Intelligence)
# ============================================================================
def _run_dijkstra_py(graph: Dict[str, Any], entry_override: Optional[str] = None) -> Dict[str, Any]:
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = {e["id"]: e for e in graph.get("edges", [])}
    if not nodes:
        return {"reachedCrownJewel": False, "path": [], "edgesUsed": [], "compromised": 0, "total": 0, "timeToCrownSec": None}

    outgoing: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges.values():
        outgoing.setdefault(e["source"], []).append(e)

    starts = [n["id"] for n in nodes.values() if n.get("status") == "compromised"]
    if not starts and entry_override and entry_override in nodes:
        starts = [entry_override]
    if not starts:
        first_iot = next((n["id"] for n in nodes.values() if n.get("type") in ("IoT", "Workstation")), None)
        if first_iot:
            starts = [first_iot]

    dist: Dict[str, float] = {s: 0.0 for s in starts}
    prev_n: Dict[str, Optional[str]] = {s: None for s in starts}
    prev_e: Dict[str, Optional[str]] = {s: None for s in starts}
    pq = [(0.0, s) for s in starts]
    visited = set()

    while pq:
        pq.sort(key=lambda x: x[0])
        d, u = pq.pop(0)
        if u in visited:
            continue
        visited.add(u)
        for edge in outgoing.get(u, []):
            if edge.get("status") == "firewalled":
                continue
            tgt = nodes.get(edge["target"])
            if not tgt or tgt.get("status") == "isolated":
                continue
            vulns = tgt.get("vulnerabilities") or []
            if len(vulns) == 0 and edge.get("protocol") != "IAM_Trust":
                continue
            cvss = max(float(tgt.get("cvss_score") or 1.0), 1.0)
            w = float(edge.get("exploit_time_sec", 5)) * (10.0 / cvss)
            nd = d + w
            if nd < dist.get(tgt["id"], float("inf")):
                dist[tgt["id"]] = nd
                prev_n[tgt["id"]] = u
                prev_e[tgt["id"]] = edge["id"]
                pq.append((nd, tgt["id"]))

    targets = [
        (dist[nid], n)
        for nid, n in nodes.items()
        if (n.get("is_crown_jewel") or n.get("is_decoy")) and nid in dist
    ]
    targets.sort(key=lambda x: x[0])

    path: List[str] = []
    edges_used: List[str] = []
    reached_cj = False
    ttc = None

    if targets:
        best_dist, chosen = targets[0]
        if not chosen.get("is_decoy"):
            reached_cj = True
            ttc = round(best_dist, 1)
        curr: Optional[str] = chosen["id"]
        while curr is not None:
            path.append(curr)
            pe = prev_e.get(curr)
            if pe:
                edges_used.append(pe)
            curr = prev_n.get(curr)
        path.reverse()
        edges_used.reverse()

    return {
        "reachedCrownJewel": reached_cj,
        "path": path,
        "edgesUsed": edges_used,
        "compromised": len(dist),
        "total": len(nodes),
        "timeToCrownSec": ttc,
    }


@app.get("/wiz/analysis")
async def wiz_security_analysis(entry: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """
    Computes:
      1. Wiz 'Toxic Combinations' (Exposure + High CVSS CVE + Privilege/Lateral Path to Crown Jewel)
      2. Optimal 1-Click Choke-Point Recommendation (Which single edge cut saves the most Blast Radius & Risk)
      3. Copy-pasteable DevSecOps Remediation Commands (AWS CLI, iptables, Docker)
    """
    snap = state.snapshot()
    base_sim = _run_dijkstra_py(snap, entry)
    nodes_by_id = {n["id"]: n for n in snap["nodes"]}
    edges_by_id = {e["id"]: e for e in snap["edges"]}

    toxic_combinations = []
    if base_sim["path"]:
        entry_node = nodes_by_id.get(base_sim["path"][0], {})
        cj_node = nodes_by_id.get(base_sim["path"][-1], {})
        iam_hops = [nodes_by_id[nid]["label"] for nid in base_sim["path"] if nodes_by_id.get(nid, {}).get("type") == "IAM"]
        critical_cves = []
        for nid in base_sim["path"]:
            critical_cves.extend(nodes_by_id.get(nid, {}).get("vulnerabilities") or [])

        path_nodes = []
        for nid in base_sim["path"]:
            n_data = nodes_by_id.get(nid, {})
            path_nodes.append({
                "id": nid,
                "label": n_data.get("label", nid),
                "type": n_data.get("type", "Unknown"),
                "is_crown_jewel": bool(n_data.get("is_crown_jewel")),
                "cvss_score": n_data.get("cvss_score", 0),
            })

        toxic_combinations.append({
            "id": "TC-01",
            "severity": "CRITICAL",
            "title": f"Edge Exposure ({entry_node.get('label', 'Entry')}) + Exploitable CVEs + Lateral Path to {cj_node.get('label', 'Crown Jewel')}",
            "factors": [
                f"Initial Access: {entry_node.get('label')} ({entry_node.get('type')}, CVSS {entry_node.get('cvss_score')})",
                f"Chained Vulnerabilities: {', '.join(critical_cves[:4]) or 'Privilege Trust Chain'}",
                f"Privilege Escalation: {', '.join(iam_hops) if iam_hops else 'Direct Service Pivot'}",
                f"Crown Jewel Impact: {cj_node.get('label')} breached in {base_sim['timeToCrownSec']}s",
            ],
            "path": base_sim["path"],
            "path_nodes": path_nodes,
        })

    candidates = []
    for eid in base_sim["edgesUsed"]:
        test_graph = copy.deepcopy(snap)
        for e in test_graph["edges"]:
            if e["id"] == eid:
                e["status"] = "firewalled"
        after_sim = _run_dijkstra_py(test_graph, entry)
        edge_obj = edges_by_id.get(eid, {})
        src_n = nodes_by_id.get(edge_obj.get("source", ""), {})
        dst_n = nodes_by_id.get(edge_obj.get("target", ""), {})
        saved_nodes = max(0, base_sim["compromised"] - after_sim["compromised"])
        protects_cj = base_sim["reachedCrownJewel"] and not after_sim["reachedCrownJewel"]
        score = (100 if protects_cj else 0) + saved_nodes * 5 + (after_sim["timeToCrownSec"] or 999) * 0.5
        candidates.append({
            "edge_id": eid,
            "source_id": edge_obj.get("source"),
            "target_id": edge_obj.get("target"),
            "protocol": edge_obj.get("protocol"),
            "source_label": src_n.get("label", edge_obj.get("source")),
            "target_label": dst_n.get("label", edge_obj.get("target")),
            "source_ip": (src_n.get("refs") or {}).get("ip", "10.0.1.0/24"),
            "target_ip": (dst_n.get("refs") or {}).get("ip", "10.0.99.100"),
            "saved_nodes": saved_nodes,
            "protects_crown_jewel": protects_cj,
            "new_time_to_crown_sec": after_sim["timeToCrownSec"],
            "score": score,
        })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    best_fix = candidates[0] if candidates else None

    remediation_cli = []
    remediation_snippets = {}
    if best_fix:
        port_map = {"SSH": 22, "HTTPS": 443, "SMB": 445, "Telnet": 23, "IAM_Trust": 443}
        port = port_map.get(best_fix["protocol"], 443)
        proto = best_fix["protocol"]
        src_ip = best_fix["source_ip"]
        dst_ip = best_fix["target_ip"]
        src_lbl = best_fix["source_label"]
        tgt_lbl = best_fix["target_label"]

        if proto == "IAM_Trust":
            remediation_cli = [
                f"# 1. AWS IAM Policy Fix — Revoke Trust Relationship ({src_lbl} -> {tgt_lbl})",
                f"aws iam update-assume-role-policy --role-name {tgt_lbl.split()[-1]} --policy-document file://deny-lateral-trust.json",
            ]
            remediation_snippets = {
                "aws_cli": f"# Revoke Inbound IAM AssumeRole Trust ({src_lbl} -> {tgt_lbl})\naws iam update-assume-role-policy \\\n  --role-name {tgt_lbl.split()[-1]} \\\n  --policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\"Principal\":{{\"AWS\":\"arn:aws:iam::*\"}},\"Action\":\"sts:AssumeRole\"}}]}}'",
                "terraform": f'# Terraform: Deny Lateral IAM AssumeRole\nresource "aws_iam_role_policy" "deny_lateral_trust" {{\n  name   = "DenyLateralTrust"\n  role   = "{tgt_lbl.split()[-1]}"\n  policy = jsonencode({{\n    Version   = "2012-10-17"\n    Statement = [{{\n      Effect    = "Deny"\n      Action    = "sts:AssumeRole"\n      Resource  = "*"\n    }}]\n  }})\n}}',
                "iptables": f"# IAM logical trust relationship: host firewalls do not apply.\n# Use AWS IAM CLI or Terraform tabs above to sever this policy link.",
                "k8s_cilium": f"# IAM logical trust relationship: use cloud IAM policies above.",
            }
        else:
            remediation_cli = [
                f"# 1. Host Firewall (iptables) — Block {proto} pivot ({src_lbl} -> {tgt_lbl})",
                f"sudo iptables -A INPUT -p tcp -s {src_ip} -d {dst_ip} --dport {port} -j DROP",
                f"# 2. AWS Security Group CLI — Revoke Inbound {proto} Rule",
                f"aws ec2 revoke-security-group-ingress --group-id sg-prod-internal --protocol tcp --port {port} --cidr {src_ip}/32",
            ]
            remediation_snippets = {
                "iptables": f"# 1. Host Firewall (iptables) — Block {proto} pivot ({src_lbl} -> {tgt_lbl})\nsudo iptables -A INPUT -p tcp -s {src_ip} -d {dst_ip} --dport {port} -j DROP\nsudo iptables-save | sudo tee /etc/iptables/rules.v4",
                "aws_cli": f"# 2. AWS Security Group CLI — Revoke Inbound {proto} Rule\naws ec2 revoke-security-group-ingress \\\n  --group-id sg-prod-internal \\\n  --protocol tcp \\\n  --port {port} \\\n  --cidr {src_ip}/32",
                "k8s_cilium": f"# 3. Kubernetes / Cilium Zero-Trust NetworkPolicy\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: block-{proto.lower()}-chokepoint\nspec:\n  podSelector:\n    matchLabels:\n      app: {tgt_lbl.split()[0].lower()}\n  policyTypes:\n  - Ingress\n  ingress:\n  - from:\n    - ipBlock:\n        cidr: 0.0.0.0/0\n        except: [{src_ip}/32]\n    ports:\n    - protocol: TCP\n      port: {port}",
                "terraform": f'# 4. Terraform: Revoke Security Group Ingress Rule\nresource "aws_security_group_rule" "deny_{proto.lower()}_pivot" {{\n  type              = "ingress"\n  from_port         = {port}\n  to_port           = {port}\n  protocol          = "tcp"\n  cidr_blocks       = ["{src_ip}/32"]\n  security_group_id = "sg-prod-internal"\n  description       = "Wiz Choke-Point: Block {proto} lateral pivot from {src_lbl}"\n}}',
            }

    return {
        "baseline": base_sim,
        "toxic_combinations": toxic_combinations,
        "optimal_chokepoint": best_fix,
        "remediation_commands": remediation_cli,
        "remediation_snippets": remediation_snippets,
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "source_mode": SOURCE_MODE,
        "nodes": len(state.nodes),
        "edges": len(state.edges),
        "connected_clients": len(bus.clients),
        "recorded_live_events": len(bus.recorded_events),
        "test_site_mounted": TEST_SITE_DIR.exists(),
        "tripwire_port": siem_adapter.tripwire_port,
    }


@app.get("/portal")
async def portal_redirect():
    return RedirectResponse(url="/site/")


@app.get("/resolver/lookup")
async def resolver_lookup(q: str = Query(..., description="IP, hostname, cloud_id, or manual alias")) -> Dict[str, Any]:
    node_id = resolver.resolve(q)
    return {
        "query": q,
        "resolved_node_id": node_id,
        "matched": node_id is not None,
        "node": state.nodes.get(node_id) if node_id else None,
    }


@app.post("/cloud/poll")
async def trigger_cloud_poll() -> Dict[str, Any]:
    result = await cloud_adapter.scan_real_infrastructure()
    return result


@app.post("/api/site/scan")
@app.get("/api/site/scan")
@app.post("/site/scan-topology")
async def trigger_website_scan() -> Dict[str, Any]:
    """
    Dynamically inspects the temporary website (HTML, JS, forms, endpoints, HTTP headers),
    extracts its architecture, and pushes the live website graph to all connected clients.
    """
    scan_data = website_scanner.scan()
    state._initial_graph = {"nodes": scan_data["nodes"], "edges": scan_data["edges"]}
    state.reset()
    resolver.rebuild_from_graph(state.snapshot())
    cloud_adapter.seed_from_graph(state.snapshot())
    await bus.broadcast_snapshot()
    logger.info("Switched to dynamic website topology: %s (%d nodes)", scan_data["title"], len(scan_data["nodes"]))
    return {
        "status": "website_scanned",
        "title": scan_data["title"],
        "nodes": len(scan_data["nodes"]),
        "edges": len(scan_data["edges"]),
        "graph": state.snapshot(),
    }


@app.post("/config/topology")
async def switch_topology(payload: Dict[str, str] = Body(...)) -> Dict[str, Any]:
    target = payload.get("topology", "website").lower()
    if target == "website":
        return await trigger_website_scan()
    elif target == "cloud":
        topology_file = SHARED_DIR / "topology.sample.json"
        if topology_file.exists():
            with open(topology_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            state._initial_graph = data
            state.reset()
            resolver.rebuild_from_graph(state.snapshot())
            cloud_adapter.seed_from_graph(state.snapshot())
            await bus.broadcast_snapshot()
            return {"status": "cloud_topology_loaded", "nodes": len(state.nodes)}
    elif target == "host":
        result = await cloud_adapter.scan_real_infrastructure()
        return {"status": "host_topology_loaded", **result}
    return {"status": "error", "message": f"Unknown topology: {target}"}


@app.post("/simulate/outbreak")
async def trigger_simulated_outbreak(entry: Optional[str] = Query(default=None), speed: float = Query(default=1.0)) -> Dict[str, Any]:
    await replay_adapter.handle_control({"action": "start", "speed": speed}, entry_id=entry)
    return {"started": True, "entry": entry, "speed": speed}


@app.get("/trap")
@app.post("/trap")
async def real_http_intrusion_trap(request: Request, target: str = Query(default="")) -> Dict[str, Any]:
    caller_ip = request.client.host if request.client else "127.0.0.1"
    now_ms = int(time.time() * 1000)
    node_id = (
        resolver.resolve(target)
        or resolver.resolve(caller_ip)
        or resolver.resolve(socket.gethostname())
        or next(iter(state.nodes.keys()), None)
    )
    if not node_id:
        return {"triggered": False, "caller_ip": caller_ip}

    comp_event = {
        "type": "node_compromised",
        "id": node_id,
        "payload": {"status": "compromised"},
        "ts": now_ms,
        "source": "siem",
    }
    await bus.publish(comp_event)

    activated_edges = []
    for eid, edge in list(state.edges.items()):
        if edge.get("source") == node_id or edge.get("target") == node_id:
            await bus.publish({
                "type": "edge_active_attack",
                "id": eid,
                "payload": {"status": "active_attack"},
                "ts": now_ms,
                "source": "siem",
            })
            activated_edges.append(eid)

    return {
        "triggered": True,
        "caller_ip": caller_ip,
        "compromised_node": node_id,
        "activated_edges": activated_edges,
    }


@app.post("/portal/attack")
async def handle_portal_attack(payload: Dict[str, Any] = Body(...), request: Request = None) -> Dict[str, Any]:
    vector = payload.get("vector", "sqli")
    input_text = payload.get("input", "")
    target_param = payload.get("target_node") or payload.get("target", "")
    caller_ip = request.client.host if request and request.client else "127.0.0.1"
    now_ms = int(time.time() * 1000)

    # If the website graph is not active, automatically dynamically scan and load it!
    if "site-web-frontend" not in state.nodes:
        await trigger_website_scan()

    nodes = state.nodes
    entry_id = resolver.resolve(target_param) if target_param else None

    if not entry_id:
        if vector == "printer_overflow":
            entry_id = next((nid for nid in ("site-printer", "node-printer", "node-printer-01") if nid in nodes), None)
        elif vector == "leaked_api_key":
            entry_id = next((nid for nid in ("site-iam-role", "node-dev-laptop", "node-admin-workstation", "iam-tmssathya") if nid in nodes), None)
        elif vector == "path_traversal":
            entry_id = next((nid for nid in ("site-web-frontend", "node-dmz-proxy", "docker-edge-api-gw", "node-api-gateway") if nid in nodes), None)
        else: # sqli
            entry_id = next((nid for nid in ("site-api-service", "site-web-frontend", "docker-edge-api-gw", "node-api-gateway", "node-dev-laptop") if nid in nodes), None)

    if not entry_id:
        entry_id = next(iter(nodes.keys()), "node-entry")

    log_line = f"timestamp={now_ms} src={caller_ip} host={entry_id} vector={vector} payload=\"{input_text[:60]}\" alert=CRITICAL_INTRUSION"
    siem_adapter.append_and_parse(log_line)

    await replay_adapter.handle_control({"action": "start", "speed": 1.5}, entry_id=entry_id)

    return {
        "status": "attack_detected",
        "entry_node": entry_id,
        "vector": vector,
        "simulated_server_response": (
            "500 Internal Server Error: Database Syntax Exception near '" + input_text[:30] + "' [CRITICAL VULNERABILITY EXPLOITED - CREDENTIALS DUMPED]"
            if vector == "sqli"
            else f"200 OK: Authentication Bypass Granted via {vector}"
        ),
    }


@app.post("/ws-source/emit")
async def trigger_ws_source_message(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    raw = json.dumps(payload)
    stale: Set[WebSocket] = set()
    for uws in list(upstream_subscribers):
        try:
            await uws.send_text(raw)
        except Exception:
            stale.add(uws)
    for uws in stale:
        upstream_subscribers.discard(uws)

    event = ws_source_adapter.normalize_message(raw)
    if not event:
        return {"accepted": False, "reason": "unresolved_or_invalid"}
    if not upstream_subscribers:
        await bus.publish(event)
    return {"accepted": True, "event": event}


@app.post("/siem/ingest")
async def ingest_siem_line(payload: Dict[str, str] = Body(...)) -> Dict[str, Any]:
    line = payload.get("line", "")
    event = siem_adapter.append_and_parse(line)
    if not event:
        return {"accepted": False, "reason": "unresolved_or_invalid"}
    if SOURCE_MODE != "live":
        await bus.publish(event)
    return {"accepted": True, "event": event}


@app.post("/config/source")
async def switch_source_mode(payload: Dict[str, str] = Body(...)) -> Dict[str, Any]:
    global SOURCE_MODE
    new_mode = payload.get("source", "").strip().lower()
    if new_mode not in ("replay", "live"):
        return {"ok": False, "error": "source must be 'replay' or 'live'"}
    SOURCE_MODE = new_mode
    if SOURCE_MODE == "live":
        await replay_adapter.handle_control({"action": "pause"})
        await cloud_adapter.scan_real_infrastructure()
        start_live_background_tasks()
    else:
        stop_live_background_tasks()
    logger.info("Switched backend SOURCE mode to: %s", SOURCE_MODE)
    return {"ok": True, "source_mode": SOURCE_MODE}


@app.post("/replay/save-recorded")
async def save_recorded_replay() -> Dict[str, Any]:
    out_file = SHARED_DIR / "recorded_events.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        for ev in bus.recorded_events:
            f.write(json.dumps(ev) + "\n")
    return {
        "saved": True,
        "count": len(bus.recorded_events),
        "path": str(out_file),
    }


@app.websocket("/upstream/ws")
async def upstream_telemetry_ws(ws: WebSocket) -> None:
    await ws.accept()
    upstream_subscribers.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        upstream_subscribers.discard(ws)
    except Exception:
        upstream_subscribers.discard(ws)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await bus.connect(ws)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if msg.get("kind") == "replay_control":
                await replay_adapter.handle_control(msg, entry_id=msg.get("entry"))
            elif msg.get("kind") == "mode_control":
                await switch_source_mode({"source": msg.get("source", "replay")})
    except WebSocketDisconnect:
        bus.disconnect(ws)
    except Exception as exc:
        logger.warning("WS connection error: %s", exc)
        bus.disconnect(ws)


@app.get("/demo")
async def demo_redirect():
    return RedirectResponse(url="/")


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, app_dir=str(BASE_DIR))

