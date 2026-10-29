# Breach Domino Simulator 🛡️⚡

> **Wiz-Inspired Security Graph Engine + Autonomous Chaos & Auto-Shield Defense Simulator**  
> An interactive full-stack cybersecurity platform that models real-world attack pathways, analyzes cloud toxic combinations, dynamically scans target web architectures, and empowers security engineers to simulate, patch, and test defensive architectures in a What-If Sandbox.

---

## 🌟 Key Features

### 1. 🌐 Real-Time Live Security Graph & Telemetry
- **Dynamic Topology Ingestion**:
  - **Dynamic Website Scanner (`WebsiteScanner`)**: Dynamically parses external web applications (DOM, forms, inputs, scripts, and HTTP headers) without hardcoding to synthesize multi-tier attack graphs.
  - **Host PC & Local Infrastructure**: Scans local interfaces, LAN devices, and Docker containers (`/cloud/poll`).
  - **Sample Enterprise Cloud Architecture**: 15-node, 30-edge enterprise topology representing perimeter proxies, DMZ runners, Kubernetes clusters, and RDS database vaults.
- **WebSocket Event Bus (`/ws`)**: High-performance asynchronous push channel streaming graph events (`node_compromised`, `edge_active_attack`, `cve_found`).

### 2. 🧪 What-If Defense Sandbox & Custom Architecture Builder
- **Movable & Drag-and-Drop Nodes**: Free canvas arrangement with persistent coordinates.
- **`+ Add Node` Cyber Security Presets**:
  - 🛡️ **Cloud WAF & Reverse Proxy** (Hardened web gateway with rate limiting & inspection)
  - 🏰 **Zero-Trust Bastion Host** (Jump box requiring MFA)
  - 🗄️ **Secure Vault Database** (High-value customer records storage / Crown Jewel)
  - 🍯 **Active Deception Honeypot** (Bait asset that traps lateral pivots)
  - 🔑 **Least-Privilege IAM Service Principal** (Scoped cloud credentials with session policy boundary)
  - ⚙️ **Internal Payments Microservice** (Internal API cluster)
- **Interactive Handle-to-Handle Linking**: Drag from any node's output handle (green) to an input handle (blue) to connect custom communication protocols (`HTTPS`, `SSH`, `IAM_Trust`, `SMB`, `Telnet`).
- **Granular Cyber Security Operations**:
  - `Remediate CVEs`: Instantly patches all software vulnerabilities (CVSS $\rightarrow$ 0).
  - `Isolate Host (Quarantine)`: Disconnects compromised machines from dynamic routing.
  - `Set as Foothold`: Test "What happens if this specific host is compromised first?".
  - `Crown Jewel Toggle`: Mark or unmark high-value target assets.
  - `Sever / Cut Edge`: Deploy firewall drop rules to sever lateral pivot routes.
- **Sandbox Simulation Engine (`▶ Run Sim`)**: Step-by-step playback at 1x or 2x speed with animated SVG particle flow (`<animateMotion>`), dynamic blast radius counting, and time-to-crown metrics.

### 3. 🎯 In-Dashboard Exploit Lab
- Trigger intrusions directly from the security dashboard without navigating away:
  - **SQL Injection**: `' OR 1=1 --` (Authentication bypass & credentials dump)
  - **Leaked AWS API Key**: `AKIAIOSFODNN7EXAMPLE` (IAM credential lateral pivot)
  - **Path Traversal**: `../../../../etc/shadow` (Arbitrary sensitive file disclosure)
  - **IoT Printer Buffer Overflow**: `HP_RAW_SOCKET_BUFFER_OVERFLOW` (CVE-2023-3519)
- Custom Attack Injector with real-time target server response inspection.

### 4. 🧙‍♂️ Wiz Toxic Combination & DevSecOps Remediation
- Automatically discovers multi-factor risk chains:
  $$\text{Perimeter Workstation} \xrightarrow{\text{CVE Exploit}} \text{Internal API} \xrightarrow{\text{IAM Role Trust}} \text{Database Crown Jewel}$$
- **AI / Dijkstra Optimal Choke-Point Solver**: Identifies the single most cost-effective edge to sever, preserving legitimate traffic while completely cutting off lateral access to crown jewels.
- **Copy-Paste DevSecOps Remediation**: Auto-generates exact CLI commands across:
  - `iptables` (Linux host firewall drop rule)
  - `aws ec2` (AWS Security Group ingress revocation)
  - `terraform` (HCL security group rule removal)
  - `k8s` (Kubernetes `NetworkPolicy` ingress isolation manifest)

### 5. 📊 Executive Before vs. After Scorecard
- Quantifies security ROI:
  - **Risk Score Reduction** (e.g., 92 $\rightarrow$ 18)
  - **Blast Radius Savings** (Nodes saved from lateral infection)
  - **Time to Crown Jewel** (Increased traversal friction or 100% Protected status)

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Client ["Frontend (Vite + React 19 + TypeScript)"]
        UI["TopologyCanvas (@xyflow/react)"]
        Toolbar["DefenseToolbar & Mode Switcher"]
        Inspector["NodeInspector & Exploit Lab"]
        Store["Zustand State Store (graphStore.ts)"]
        Dijkstra["Dijkstra Simulation Engine (simulate.ts)"]
        UI <--> Store
        Toolbar <--> Store
        Inspector <--> Store
        Store <--> Dijkstra
    end

    subgraph Server ["Backend (Python 3.12 + FastAPI)"]
        Main["FastAPI Router (main.py)"]
        Bus["Async EventBus (bus.py)"]
        State["GraphState (graph_state.py)"]
        Replay["Red-Team Chaos Engine (replay.py)"]
        Scanner["WebsiteScanner (website_scanner.py)"]
        SIEM["SIEM Adapter (siem.py)"]
        Cloud["Cloud & Infrastructure Adapter (cloud.py)"]
        
        Main <--> Bus
        Bus <--> State
        Main <--> Scanner
        Main <--> Replay
        Main <--> SIEM
        Main <--> Cloud
    end

    subgraph Target ["Target Test Environment"]
        WebSite["Apex Cloud Portal (HTML/JS/DOM)"]
        Tripwire["Port 8022 Honeypot Listener"]
    end

    Store -- WebSocket (/ws) --> Bus
    Store -- REST APIs (/portal/attack, /api/site/scan) --> Main
    Scanner -- HTTP Probe & File Inspection --> WebSite
    SIEM -- Alert Ingestion --> Bus
```

---

## 📁 Repository Structure

```
breach/
├── backend/                        # Python FastAPI backend server
│   ├── adapters/
│   │   ├── cloud.py                # Host PC, LAN & Docker container scanner
│   │   ├── replay.py               # Autonomous Red-Team chaos outbreak engine
│   │   ├── siem.py                 # SIEM alert ingestion and regex log parser
│   │   ├── website_scanner.py      # Dynamic DOM & architecture scanner
│   │   └── ws_source.py            # Upstream external telemetry adapter
│   ├── bus.py                      # Multi-client async WebSocket event broadcaster
│   ├── graph_state.py              # In-memory graph model & snapshot management
│   ├── main.py                     # API routes, static mounts, and WS endpoints
│   ├── resolver.py                 # Asset IP/hostname-to-node ID resolver
│   └── requirements.txt            # Python dependencies (fastapi, uvicorn, pydantic)
│
├── frontend/                       # React 19 + TypeScript + Vite frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── AddNodeModal.tsx    # Cyber security asset deployer & presets
│   │   │   ├── AttackEdge.tsx      # Custom SVG edge with particle animation
│   │   │   ├── AttackNode.tsx      # Custom React Flow node with CVSS & status badges
│   │   │   ├── DefenseToolbar.tsx  # Mode switcher, sandbox controls, and defense tools
│   │   │   ├── Hud.tsx             # Blast radius, time-to-crown, and narrative log
│   │   │   ├── NodeInspector.tsx   # Asset inspector, Exploit Lab, and Wiz Intel
│   │   │   ├── Scorecard.tsx       # Executive Before vs. After security ROI modal
│   │   │   └── TopologyCanvas.tsx  # Interactive canvas with drag & handle connections
│   │   ├── engine/
│   │   │   ├── simulate.ts         # Dijkstra shortest attack path & time calculation
│   │   │   └── simulate.test.ts    # Vitest automated test suite
│   │   └── store/
│   │       ├── graphStore.ts       # Zustand centralized state store
│   │       └── socket.ts           # Resilient WebSocket client with exponential backoff
│   ├── package.json
│   └── vite.config.ts
│
├── shared/                         # Shared data contracts and sample configurations
│   ├── manual_map.json             # Manual asset mappings
│   ├── sample_events.jsonl         # Baseline attack narrative sequence
│   ├── topology.sample.json        # 15-node enterprise cloud topology
│   └── types.ts                    # Shared TypeScript interfaces
│
└── test_site/                      # Realistic vulnerable target web application
    ├── apex_cloud_customer_portal_test_target.html
    ├── breach_sentinel.js          # Client-side telemetry SDK
    └── index.html
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python**: 3.10+ (tested with Python 3.12)
- **Node.js**: v18+ and `npm`

---

### Step 1: Start the Backend Server

```bash
# Navigate to project root
cd breach

# Activate Python virtual environment (Windows PowerShell)
.venv\Scripts\Activate.ps1

# (Optional) Install dependencies if running for the first time
pip install -r backend/requirements.txt

# Start the FastAPI daemon server
python backend/main.py
```
* The backend will start on **`http://localhost:8000`**
* Health check: `http://localhost:8000/health`
* Live target portal: `http://localhost:8000/site/`

---

### Step 2: Start the Frontend Application

```bash
# In a second terminal
cd breach/frontend

# Install node dependencies
npm install

# Start Vite dev server
npm run dev
```
* Open your browser at **`http://localhost:5173`**

---

### Step 3: Run Automated Unit Tests

```bash
# In frontend directory
npm test
```
* Executes Vitest test suite verifying Dijkstra path calculations, decoy honeypot traps, and patch logic.

---

## 🎮 Interactive Walkthrough

### 1. Simulating an Intrusion Wave
1. Open the **Exploit Lab** tab on the right panel.
2. Under **1-Click Exploit Presets**, click **`⚡ Fire Exploit`** on **SQL Injection** or **Path Traversal**.
3. Watch the infection wave propagate across the graph with glowing red borders and animated SVG attack particles traversing the edges.

### 2. Experimenting in What-If Sandbox Mode
1. In the top toolbar, click **`What-If Sandbox`** (or press key `W`).
2. Notice the amber sandbox banner indicating that changes are isolated from live infrastructure.
3. Test your defensive strategies:
   - **Sever an Edge**: Click **`✂ Cut Edge`**, then click an edge leading to the database.
   - **Remediate a Server**: Click **`🛡️ Patch Node`**, then click the API gateway.
   - **Deploy a Honeypot**: Click **`🎯 Drop Decoy`** to place an active bait service.
   - **AI Choke-Point**: Click **`⚡ Auto-Shield`** to let the Dijkstra optimizer compute and sever the optimal bottleneck.
4. Click **`▶ Run Sim`** to watch the simulated outbreak attempt to penetrate your defended architecture.
5. If protected, the HUD displays **`PROTECTED 🛡️`** or **`TRAPPED 🍯`**.
6. Click **`📊 Scorecard`** to view the quantifiable reduction in risk and blast radius.

### 3. Designing Custom Architectures
1. In What-If mode, drag existing nodes to organize your tiers.
2. Click **`+ Add Node`** in the toolbar to deploy new security components (e.g., Cloud WAF, Bastion Host, or Encrypted Vault).
3. Drag from a green handle to a blue handle to link components together.
4. Click **`▶ Run Sim`** to verify your design's breach resistance before deploying to production!

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/health` | `GET` | Health status, connected WS clients, and active mode |
| `/api/site/scan` | `POST` | Dynamically inspects `test_site` and pushes website graph |
| `/config/topology` | `POST` | Switch active graph (`website`, `cloud`, or `host`) |
| `/portal/attack` | `POST` | Injects exploit payload (`sqli`, `leaked_api_key`, `path_traversal`) |
| `/wiz/analysis` | `GET` | Computes toxic combinations & optimal choke point |
| `/cloud/poll` | `POST` | Scans local host PC, LAN interfaces, and Docker daemon |
| `/ws` | `WS` | Asynchronous WebSocket push channel |

---

## ⚖️ License
MIT License. Built for advanced red-team / blue-team security simulation and DevSecOps architecture verification.
