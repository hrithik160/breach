
    let ws = null;
    let liveGraph = { nodes: [], edges: [] };
    let whatIfGraph = null;
    let uiMode = 'live';
    let activeTool = null;
    let baselineSim = null;
    let customEntryId = null;
    let currentSourceMode = 'replay';
    let lastWizAnalysis = null;
    let selectedNodeId = null;
    let highlightedEdgeId = null;
    let activeCliTab = 'iptables';
    let wireLogEntries = [];
    let currentLogFilter = 'all';

    function calcWeight(edge, target) {
      const cvss = Math.max(target.cvss_score ?? 1, 1);
      return edge.exploit_time_sec * (10 / cvss);
    }

    function canTraverse(edge, target) {
      if (edge.status === 'firewalled') return false;
      if (target.status === 'isolated') return false;
      const hasVuln = Array.isArray(target.vulnerabilities) && target.vulnerabilities.length > 0;
      if (!hasVuln && edge.protocol !== 'IAM_Trust') return false;
      return true;
    }

    function formatHopLog(source, target, edge) {
      const cve = (target.vulnerabilities && target.vulnerabilities.length > 0) ? ` (${target.vulnerabilities[0]})` : '';
      let action = `${edge.protocol} pivot from ${source.label} to ${target.label}${cve}`;
      if (edge.protocol === 'HTTPS') action = `HTTPS exploit from ${source.label} hitting web service on ${target.label}${cve}`;
      if (edge.protocol === 'SMB') action = `SMB Pass-the-Hash lateral movement from ${source.label} to ${target.label}`;
      if (edge.protocol === 'IAM_Trust') action = `IAM Trust privilege escalation from ${source.label} to ${target.label}`;
      if (target.is_decoy) action += ' [HONEYPOT TRIGGERED - ATTACKER TRAPPED]';
      else if (target.is_crown_jewel) action += ' [CRITICAL - CROWN JEWEL BREACHED]';
      return action;
    }

    function simulate(graph, entryOverride) {
      const total = graph.nodes.length;
      if (total === 0) return { reachedCrownJewel: false, path: [], edgesUsed: [], timeline: [], blastRadius: { compromised: 0, total: 0 }, timeToCrownSec: null };
      const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
      const edgeMap = new Map(graph.edges.map(e => [e.id, e]));
      const outgoing = new Map();
      for (const e of graph.edges) {
        if (!outgoing.has(e.source)) outgoing.set(e.source, []);
        outgoing.get(e.source).push(e);
      }

      let starts = graph.nodes.filter(n => n.status === 'compromised').map(n => n.id);
      if (starts.length === 0 && entryOverride && nodeMap.has(entryOverride)) {
        starts = [entryOverride];
      }
      if (starts.length === 0) {
        const firstIot = graph.nodes.find(n => n.type === 'IoT' || n.type === 'Workstation');
        if (firstIot) starts = [firstIot.id];
      }
      if (starts.length === 0) {
        return { reachedCrownJewel: false, path: [], edgesUsed: [], timeline: [], blastRadius: { compromised: 0, total }, timeToCrownSec: null };
      }

      const dist = new Map();
      const prevN = new Map();
      const prevE = new Map();
      const pq = [];
      for (const s of starts) {
        dist.set(s, 0); prevN.set(s, null); prevE.set(s, null);
        pq.push({ nodeId: s, dist: 0 });
      }
      const visited = new Set();
      while (pq.length > 0) {
        pq.sort((a, b) => a.dist - b.dist);
        const { nodeId: u, dist: d } = pq.shift();
        if (visited.has(u)) continue;
        visited.add(u);
        for (const edge of (outgoing.get(u) || [])) {
          const tgt = nodeMap.get(edge.target);
          if (!tgt || !canTraverse(edge, tgt)) continue;
          const nd = d + calcWeight(edge, tgt);
          if (nd < (dist.get(tgt.id) ?? Infinity)) {
            dist.set(tgt.id, nd); prevN.set(tgt.id, u); prevE.set(tgt.id, edge.id);
            pq.push({ nodeId: tgt.id, dist: nd });
          }
        }
      }

      const targets = graph.nodes.filter(n => (n.is_crown_jewel || n.is_decoy) && dist.has(n.id)).map(n => ({ node: n, dist: dist.get(n.id) }));
      targets.sort((a, b) => a.dist - b.dist);
      let reachedCrownJewel = false, timeToCrownSec = null, path = [], edgesUsed = [];
      if (targets.length > 0) {
        const chosen = targets[0];
        if (!chosen.node.is_decoy) {
          reachedCrownJewel = true;
          timeToCrownSec = Math.round(chosen.dist * 10) / 10;
        }
        let curr = chosen.node.id;
        while (curr !== null) {
          path.push(curr);
          if (prevE.get(curr)) edgesUsed.push(prevE.get(curr));
          curr = prevN.get(curr) ?? null;
        }
        path.reverse(); edgesUsed.reverse();
      }

      const timeline = [];
      if (path.length > 0) {
        const st = nodeMap.get(path[0]);
        timeline.push({ t: 0, nodeId: path[0], viaEdge: null, log: `Patient Zero: Initial breach detected on ${st.label} (${st.type})` });
        for (let i = 0; i < edgesUsed.length; i++) {
          const ed = edgeMap.get(edgesUsed[i]);
          const sn = nodeMap.get(path[i]);
          const tn = nodeMap.get(path[i + 1]);
          timeline.push({ t: Math.round((dist.get(tn.id) || 0) * 10) / 10, nodeId: tn.id, viaEdge: ed.id, log: formatHopLog(sn, tn, ed) });
        }
      }

      return { reachedCrownJewel, path, edgesUsed, timeline, blastRadius: { compromised: dist.size, total }, timeToCrownSec };
    }

    function calcRisk(sim) {
      if (!sim.blastRadius.total || !sim.blastRadius.compromised) return 0;
      const r = sim.blastRadius.compromised / sim.blastRadius.total;
      if (sim.reachedCrownJewel) {
        const tf = sim.timeToCrownSec !== null ? Math.max(0, 30 - Math.min(sim.timeToCrownSec, 30)) : 10;
        return Math.min(100, Math.round(50 + r * 20 + tf));
      }
      return Math.min(45, Math.round(r * 45));
    }

    function getActiveGraph() {
      return uiMode === 'whatif' && whatIfGraph ? whatIfGraph : liveGraph;
    }

    function logMsg(label, obj) {
      const time = new Date().toLocaleTimeString();
      const entryText = `[${time}] ${label}: ${typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)}`;
      
      let cat = 'general';
      const lower = (label + ' ' + JSON.stringify(obj)).toLowerCase();
      if (lower.includes('attack') || lower.includes('outbreak') || lower.includes('intrusion') || lower.includes('compromised')) cat = 'intrusion';
      else if (lower.includes('patch') || lower.includes('firewall') || lower.includes('choke') || lower.includes('shield') || lower.includes('isolate')) cat = 'defense';
      else if (lower.includes('cve') || lower.includes('vuln')) cat = 'cve';

      wireLogEntries.unshift({ time, label, obj, text: entryText, cat });
      if (wireLogEntries.length > 150) wireLogEntries.pop();
      renderWireLogs();
    }

    function renderWireLogs() {
      const el = document.getElementById('log');
      if (!el) return;
      const filtered = currentLogFilter === 'all'
        ? wireLogEntries
        : wireLogEntries.filter(e => e.cat === currentLogFilter);
      el.textContent = filtered.map(e => e.text).join('

') || '(No events in this category yet)';
    }

    function filterWireLogs(cat, el) {
      currentLogFilter = cat;
      document.querySelectorAll('.log-filter-chip').forEach(c => c.classList.remove('active'));
      if (el) el.classList.add('active');
      renderWireLogs();
    }

    function clearWireLogs() {
      wireLogEntries = [];
      renderWireLogs();
    }

    function switchInspectorTab(tab) {
      document.getElementById('tab-btn-inspector').classList.toggle('active-tab-btn', tab === 'inspector');
      document.getElementById('tab-btn-wirelog').classList.toggle('active-tab-btn', tab === 'wirelog');
      document.getElementById('tab-content-inspector').style.display = tab === 'inspector' ? 'block' : 'none';
      document.getElementById('tab-content-wirelog').style.display = tab === 'wirelog' ? 'block' : 'none';
    }

    function switchCliTab(tab) {
      activeCliTab = tab;
      document.querySelectorAll('.cli-tab').forEach(b => {
        b.classList.toggle('active-cli-tab', b.dataset.tab === tab);
      });
      const codeBox = document.getElementById('cli-code-text');
      if (codeBox && lastWizAnalysis && lastWizAnalysis.remediation_snippets) {
        codeBox.textContent = lastWizAnalysis.remediation_snippets[tab] || (lastWizAnalysis.remediation_commands || []).join('
') || '# No commands needed';
      }
    }

    function copyActiveCliSnippet() {
      const codeBox = document.getElementById('cli-code-text');
      if (!codeBox) return;
      const text = codeBox.textContent;
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-cli-btn');
        if (btn) {
          const orig = btn.textContent;
          btn.textContent = '✓ Copied!';
          btn.style.color = '#34d399';
          setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
        }
      });
    }

    async function toggleChokepointFix() {
      if (!lastWizAnalysis || !lastWizAnalysis.optimal_chokepoint) {
        await refreshWizInsights();
      }
      const best = lastWizAnalysis && lastWizAnalysis.optimal_chokepoint;
      if (!best) return;
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const edge = whatIfGraph.edges.find(e => e.id === best.edge_id);
      if (edge) {
        edge.status = edge.status === 'firewalled' ? 'open' : 'firewalled';
        logMsg('WHAT-IF CHOKE-POINT TOGGLE', { edgeId: best.edge_id, status: edge.status });
        render();
        await refreshWizInsights();
      }
    }

    function highlightChokepointOnMap() {
      const best = lastWizAnalysis && lastWizAnalysis.optimal_chokepoint;
      if (!best) return;
      highlightedEdgeId = best.edge_id;
      render();
      setTimeout(() => {
        highlightedEdgeId = null;
        render();
      }, 4000);
    }

    function selectNodeForInspector(nodeId) {
      const g = getActiveGraph();
      const node = g.nodes.find(n => n.id === nodeId);
      if (node) {
        selectedNodeId = nodeId;
        renderNodeInspector(node);
        render();
        switchInspectorTab('inspector');
      }
    }

    function renderNodeInspector(node) {
      const body = document.getElementById('node-inspector-body');
      if (!body) return;
      if (!node) {
        body.innerHTML = `
          <div class="empty-inspector">
            <div style="font-size:24px;margin-bottom:6px;">🎯</div>
            <b style="color:#e2e8f0;">No Node Selected</b><br>
            <span style="color:#64748b;font-size:10.5px;">Click any device or server on the graph to view posture, CVEs, lateral paths, and apply instant defenses.</span>
          </div>`;
        return;
      }

      const isCrown = node.is_crown_jewel;
      const isComp = node.status === 'compromised';
      const isDecoy = node.is_decoy;
      const isIso = node.status === 'isolated';
      const cvss = node.cvss_score || 0;
      const vulns = node.vulnerabilities || [];
      const refs = node.refs || {};

      let statusHtml = isComp
        ? '<span class="status-pill comp">🚨 COMPROMISED</span>'
        : (isIso ? '<span class="status-pill iso">🔒 ISOLATED</span>' : '<span class="status-pill sec">🛡️ SECURE</span>');
      if (isCrown) statusHtml += ' <span class="status-pill crown">👑 CROWN JEWEL</span>';
      if (isDecoy) statusHtml += ' <span class="status-pill decoy">🍯 HONEYPOT</span>';

      const cvssPct = Math.min(100, Math.round((cvss / 10) * 100));
      const cvssColor = cvss >= 8.5 ? '#ef4444' : (cvss >= 6.0 ? '#f59e0b' : (cvss > 0 ? '#38bdf8' : '#10b981'));
      const cvssSeverity = cvss >= 8.5 ? 'CRITICAL' : (cvss >= 6.0 ? 'HIGH' : (cvss > 0 ? 'MEDIUM' : 'CLEAN'));

      const g = getActiveGraph();
      const inEdges = g.edges.filter(e => e.target === node.id);
      const outEdges = g.edges.filter(e => e.source === node.id);

      let cveChips = vulns.length > 0
        ? vulns.map(c => `<span class="cve-chip" title="Click to view CVE details on NVD" onclick="window.open('https://nvd.nist.gov/vuln/detail/${c}','_blank')">⚠️ ${c}</span>`).join('')
        : '<span style="color:#10b981;font-size:11px;">✓ No known CVEs detected (Remediated)</span>';

      let connRows = '';
      inEdges.forEach(e => {
        const srcNode = g.nodes.find(n => n.id === e.source) || { label: e.source };
        const isFw = e.status === 'firewalled';
        connRows += `
          <div class="conn-row">
            <div><span style="color:#38bdf8;font-size:9.5px;font-weight:bold;">⬇ IN (${e.protocol})</span> <span style="color:#cbd5e1;">${srcNode.label}</span></div>
            <button class="conn-cut-btn" onclick="toggleEdgeFromInspector('${e.id}')">${isFw ? '✓ Re-open' : '✂️ Sever'}</button>
          </div>`;
      });
      outEdges.forEach(e => {
        const tgtNode = g.nodes.find(n => n.id === e.target) || { label: e.target };
        const isFw = e.status === 'firewalled';
        connRows += `
          <div class="conn-row">
            <div><span style="color:#f59e0b;font-size:9.5px;font-weight:bold;">⬆ OUT (${e.protocol})</span> <span style="color:#cbd5e1;">${tgtNode.label}</span></div>
            <button class="conn-cut-btn" onclick="toggleEdgeFromInspector('${e.id}')">${isFw ? '✓ Re-open' : '✂️ Sever'}</button>
          </div>`;
      });
      if (!connRows) connRows = '<div style="color:#64748b;font-size:10px;padding:4px;">No active lateral connections.</div>';

      const typeIconMap = {
        'Server': '🖥️',
        'Workstation': '💻',
        'IoT': '🖨️',
        'IAM': '🔑',
        'Decoy': '🍯',
        'Database': '🗄️'
      };
      const icon = typeIconMap[node.type] || '🌐';

      body.innerHTML = `
        <div class="inspector-card">
          <div class="node-header-row">
            <div class="node-title-group">
              <h4>${icon} ${node.label}</h4>
              <small>ID: ${node.id} &bull; Type: ${node.type}</small>
            </div>
            <div style="text-align:right;">${statusHtml}</div>
          </div>

          <div class="node-cvss-meter">
            <div class="cvss-label-row">
              <span style="color:#94a3b8;">Vulnerability Score</span>
              <span style="color:${cvssColor};">${cvss} / 10.0 (${cvssSeverity})</span>
            </div>
            <div class="cvss-bar-wrap">
              <div class="cvss-bar-fill" style="width:${cvssPct}%;background:${cvssColor};"></div>
            </div>
          </div>

          <div class="node-details-grid">
            <div class="node-meta-item">
              <div class="node-meta-label">IP Address</div>
              <div class="node-meta-val" title="Click to copy" style="cursor:pointer;" onclick="navigator.clipboard.writeText('${refs.ip || '10.0.0.1'}')">${refs.ip || '10.0.0.1'} 📋</div>
            </div>
            <div class="node-meta-item">
              <div class="node-meta-label">Hostname</div>
              <div class="node-meta-val">${refs.hostname || node.id}</div>
            </div>
            <div class="node-meta-item">
              <div class="node-meta-label">Cloud ID</div>
              <div class="node-meta-val">${refs.cloud_id || 'i-' + node.id.slice(-6)}</div>
            </div>
          </div>

          <div style="margin-top:6px;">
            <b style="color:#cbd5e1;font-size:10.5px;">Detected CVEs (${vulns.length}):</b>
            <div class="cve-chips-wrap">${cveChips}</div>
          </div>

          <div style="margin-top:8px;">
            <b style="color:#cbd5e1;font-size:10.5px;">Network Pivot Links (${inEdges.length + outEdges.length}):</b>
            <div class="conn-list">${connRows}</div>
          </div>

          <div class="inspector-actions">
            <button class="btn-action patch" onclick="patchInspectedNode('${node.id}')">🩹 Patch CVEs (CVSS → 0)</button>
            <button class="btn-action isolate" onclick="isolateInspectedNode('${node.id}')">🔒 Isolate Host</button>
            <button class="btn-action attack" onclick="launchOutbreakFromNode('${node.id}')">🚀 Patient Zero Outbreak</button>
          </div>
        </div>
      `;
    }

    function patchInspectedNode(nodeId) {
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const n = whatIfGraph.nodes.find(nd => nd.id === nodeId);
      if (n) {
        n.vulnerabilities = [];
        n.cvss_score = 0;
        logMsg('WHAT-IF PATCH NODE', { nodeId, cvss_score: 0 });
        render();
        renderNodeInspector(n);
        refreshWizInsights();
      }
    }

    function isolateInspectedNode(nodeId) {
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const node = whatIfGraph.nodes.find(n => n.id === nodeId);
      if (node) {
        node.status = node.status === 'isolated' ? 'secure' : 'isolated';
        whatIfGraph.edges.forEach(e => {
          if (e.source === nodeId || e.target === nodeId) {
            e.status = node.status === 'isolated' ? 'firewalled' : 'open';
          }
        });
        logMsg('WHAT-IF ISOLATE NODE', { nodeId, status: node.status });
        render();
        renderNodeInspector(node);
        refreshWizInsights();
      }
    }

    function launchOutbreakFromNode(nodeId) {
      customEntryId = nodeId;
      refreshWizInsights();
      sendCtrl('start', 1, nodeId);
      logMsg('OUTBREAK TRIGGERED AT PATIENT ZERO', { entryNode: nodeId });
    }

    function toggleEdgeFromInspector(edgeId) {
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const e = whatIfGraph.edges.find(ed => ed.id === edgeId);
      if (e) {
        e.status = e.status === 'firewalled' ? 'open' : 'firewalled';
        logMsg('WHAT-IF EDGE STATUS TOGGLE', { edgeId, status: e.status });
        render();
        const g = getActiveGraph();
        const curr = g.nodes.find(n => n.id === selectedNodeId);
        if (curr) renderNodeInspector(curr);
        refreshWizInsights();
      }
    }

    async function refreshWizInsights() {
      try {
        const q = customEntryId ? `?entry=${encodeURIComponent(customEntryId)}` : '';
        const res = await fetch('/wiz/analysis' + q);
        const data = await res.json();
        lastWizAnalysis = data;
        const box = document.getElementById('wiz-insights');
        const statusPill = document.getElementById('tc-status-pill');
        const tc = (data.toxic_combinations && data.toxic_combinations[0]) || null;
        const best = data.optimal_chokepoint;

        if (statusPill) {
          if (tc) {
            statusPill.style.background = '#450a0a';
            statusPill.style.color = '#fca5a5';
            statusPill.style.borderColor = '#b91c1c';
            statusPill.textContent = '1 CRITICAL DETECTED';
          } else {
            statusPill.style.background = '#064e3b';
            statusPill.style.color = '#6ee7b7';
            statusPill.style.borderColor = '#059669';
            statusPill.textContent = '0 DETECTED (SECURE)';
          }
        }

        let html = '';
        if (tc) {
          html += `<div class="wiz-title">
            <span>☣️ WIZ TOXIC COMBINATION DETECTED</span>
            <span style="color:#f87171;font-size:10.5px;padding:2px 7px;background:rgba(239,68,68,0.15);border:1px solid #dc2626;border-radius:4px;">${tc.severity}</span>
          </div>`;
          html += `<div style="color:#e2e8f0;margin-bottom:6px;font-size:12px;"><b>${tc.title}</b></div>`;

          // Interactive Attack Path Breadcrumbs
          if (tc.path_nodes && tc.path_nodes.length > 0) {
            html += `<div style="font-size:10px;color:#94a3b8;margin-bottom:2px;"><b>INTERACTIVE ATTACK PATH (Click node to inspect):</b></div>`;
            html += `<div class="attack-flow-wrap">`;
            tc.path_nodes.forEach((pn, i) => {
              const isLast = i === tc.path_nodes.length - 1;
              const crownCls = pn.is_crown_jewel ? 'crown' : '';
              html += `<span class="flow-step ${crownCls}" onclick="selectNodeForInspector('${pn.id}')" title="Inspect ${pn.label}">
                ${pn.is_crown_jewel ? '👑' : '•'} ${pn.label.slice(0, 18)}
              </span>`;
              if (!isLast) {
                html += `<span class="flow-arrow">➔</span>`;
              }
            });
            html += `</div>`;
          }

          html += `<div style="color:#94a3b8;font-size:11px;margin:6px 0 8px 0;line-height:1.5;">• ${tc.factors.join('<br>• ')}</div>`;
        }

        if (best) {
          const g = getActiveGraph();
          const currentEdge = g.edges.find(e => e.id === best.edge_id);
          const isCurrentlySevered = currentEdge && currentEdge.status === 'firewalled';

          let impactText = best.protects_crown_jewel
            ? '🛡️ <b>100% BLOCKS Crown Jewel Breach!</b>'
            : `saves <b>${best.saved_nodes} nodes</b>`;

          html += `
            <div class="chokepoint-card">
              <div class="chokepoint-title">
                <span>✨ AI / Dijkstra Optimal Choke-Point Fix</span>
                <span style="font-size:10px;background:#0369a1;color:#e0f2fe;padding:2px 6px;border-radius:3px;">MIN-CUT BEST</span>
              </div>
              <div style="font-size:11px;color:#e2e8f0;margin-bottom:4px;">
                Sever <code>${best.edge_id}</code> (${best.protocol}: <b>${best.source_label}</b> → <b>${best.target_label}</b>)
              </div>
              <div style="font-size:11px;color:#34d399;">
                Impact: ${impactText} ${best.new_time_to_crown_sec ? `&bull; Delays path to ${best.new_time_to_crown_sec}s` : ''}
              </div>
              <div class="chokepoint-btns">
                <button class="btn-choke ${isCurrentlySevered ? 'btn-choke-revert' : 'btn-choke-apply'}" onclick="toggleChokepointFix()">
                  ${isCurrentlySevered ? '↩️ Revert Choke-Point Fix' : '⚡ 1-Click Auto-Shield Fix'}
                </button>
                <button class="btn-choke btn-choke-highlight" onclick="highlightChokepointOnMap()">
                  🎯 Highlight on Map
                </button>
              </div>
            </div>
          `;
        }

        // Multi-Platform DevSecOps Remediation Tabs
        const snippets = data.remediation_snippets || {};
        const defaultSnippet = snippets[activeCliTab] || (data.remediation_commands || []).join('
') || '# No commands needed';

        html += `
          <div class="cli-tab-bar">
            <button class="cli-tab ${activeCliTab === 'iptables' ? 'active-cli-tab' : ''}" data-tab="iptables" onclick="switchCliTab('iptables')">Host (iptables)</button>
            <button class="cli-tab ${activeCliTab === 'aws_cli' ? 'active-cli-tab' : ''}" data-tab="aws_cli" onclick="switchCliTab('aws_cli')">AWS Security Group</button>
            <button class="cli-tab ${activeCliTab === 'k8s_cilium' ? 'active-cli-tab' : ''}" data-tab="k8s_cilium" onclick="switchCliTab('k8s_cilium')">K8s NetworkPolicy</button>
            <button class="cli-tab ${activeCliTab === 'terraform' ? 'active-cli-tab' : ''}" data-tab="terraform" onclick="switchCliTab('terraform')">Terraform (IaC)</button>
          </div>
          <div class="cli-code-wrap">
            <button id="copy-cli-btn" class="copy-cli-btn" onclick="copyActiveCliSnippet()">📋 Copy</button>
            <pre id="cli-code-text" class="cli-box">${defaultSnippet}</pre>
          </div>
        `;

        box.innerHTML = html || '<i>No active Toxic Combinations detected.</i>';
      } catch (e) {
        console.error('Failed to refresh Wiz insights:', e);
      }
    }

    function render() {
      const g = getActiveGraph();
      const sim = simulate(g, customEntryId);
      const risk = calcRisk(sim);

      document.getElementById('counts').textContent = `${g.nodes.length} nodes, ${g.edges.length} edges`;
      document.getElementById('hud-blast').textContent = `${sim.blastRadius.compromised} / ${sim.blastRadius.total} nodes`;
      document.getElementById('hud-time').textContent = sim.timeToCrownSec !== null ? `${sim.timeToCrownSec}s` : (sim.path.length > 1 ? 'TRAPPED AT DECOY' : 'Safe / Blocked');
      document.getElementById('hud-risk').textContent = `${risk} / 100`;
      document.getElementById('crown-status').textContent = sim.reachedCrownJewel ? '🚨 CROWN JEWEL REACHABLE' : '🛡️ CROWN JEWEL PROTECTED';

      if (uiMode === 'whatif' && baselineSim) {
        const savedNodes = Math.max(0, baselineSim.blastRadius.compromised - sim.blastRadius.compromised);
        const savedRisk = Math.max(0, calcRisk(baselineSim) - risk);
        document.getElementById('hud-saved').textContent = `-${savedNodes} nodes | -${savedRisk} risk (${baselineSim.blastRadius.compromised}/${baselineSim.blastRadius.total} → ${sim.blastRadius.compromised}/${sim.blastRadius.total})`;
      } else {
        document.getElementById('hud-saved').textContent = 'Enter What-If mode to test defenses';
      }

      const svg = document.getElementById('topo-svg');
      const nodeMap = {};
      g.nodes.forEach((n, idx) => {
        const x = (n.pos && n.pos.x) ? n.pos.x : (100 + (idx % 5) * 210);
        const y = (n.pos && n.pos.y) ? n.pos.y : (80 + Math.floor(idx / 5) * 160);
        nodeMap[n.id] = { ...n, x, y };
      });

      const dijkstraEdges = new Set(sim.edgesUsed);
      let svgHtml = '';
      g.edges.forEach(e => {
        const s = nodeMap[e.source], t = nodeMap[e.target];
        if (!s || !t) return;
        const isFirewalled = e.status === 'firewalled';
        const isAttack = e.status === 'active_attack';
        const isDijkstra = dijkstraEdges.has(e.id);
        const isHighlighted = (highlightedEdgeId === e.id);
        let cls = isFirewalled ? 'edge-firewalled' : (isAttack ? 'edge-attack' : (isHighlighted ? 'edge-highlight-pulse' : (isDijkstra ? 'edge-dijkstra' : '')));
        let stroke = isFirewalled ? '#475569' : (isAttack ? '#ef4444' : (isHighlighted ? '#38bdf8' : (isDijkstra ? '#f97316' : '#334155')));
        let sw = isHighlighted ? 4.5 : (isAttack ? 2.8 : 1.8);
        const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
        svgHtml += `<g style="cursor:pointer;" onclick="onEdgeClick('${e.id}')">`;
        svgHtml += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="transparent" stroke-width="14" />`;
        svgHtml += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${stroke}" stroke-width="${sw}" class="${cls}" />`;
        svgHtml += `<text x="${mx}" y="${my - 5}" fill="${isFirewalled ? '#64748b' : '#94a3b8'}" font-size="9.5" text-anchor="middle">${isFirewalled ? '✂️ BLOCKED' : e.protocol}</text>`;
        svgHtml += `</g>`;
      });

      const pathSet = new Set(sim.path);
      Object.values(nodeMap).forEach(n => {
        const isComp = n.status === 'compromised';
        const isDecoy = n.is_decoy;
        const inPath = pathSet.has(n.id);
        const fill = isDecoy ? '#065f46' : (isComp ? '#dc2626' : (n.cvss_score === 0 ? '#0f766e' : '#1e293b'));
        const stroke = n.is_crown_jewel ? '#fbbf24' : (isDecoy ? '#34d399' : (isComp ? '#f87171' : (inPath ? '#f97316' : '#475569')));
        const sw = (n.is_crown_jewel || isDecoy || inPath) ? 3.2 : 2;
        const cls = isComp ? 'node-comp-circle' : '';
        svgHtml += `<g transform="translate(${n.x},${n.y})" style="cursor:pointer;" onclick="onNodeClick('${n.id}')">`;
        if (selectedNodeId === n.id) {
          svgHtml += `<circle r="23" fill="none" stroke="#38bdf8" stroke-width="2.5" class="node-selected-ring" />`;
        }
        svgHtml += `<circle r="17" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" class="${cls}" />`;
        svgHtml += `<text y="4" fill="#f8fafc" font-size="9" text-anchor="middle" font-weight="bold">${n.type.slice(0,3).toUpperCase()}</text>`;
        svgHtml += `<text y="30" fill="${isComp ? '#fca5a5' : '#cbd5e1'}" font-size="10" text-anchor="middle">${n.label.slice(0, 22)}</text>`;
        svgHtml += `</g>`;
      });
      svg.innerHTML = svgHtml;

      const kc = document.getElementById('killchain');
      if (sim.timeline.length === 0) {
        kc.innerHTML = '<i>No active attack path to Crown Jewel (all entry paths blocked or no compromised node selected).</i>';
      } else {
        kc.innerHTML = sim.timeline.map(tick =>
          `<div class="tick-item ${tick.log.includes('HONEYPOT') ? 'tick-decoy' : ''}"><b>[t=${tick.t}s]</b> ${tick.log}</div>`
        ).join('');
      }
    }

    function toggleWhatIfMode() {
      const btn = document.getElementById('btn-whatif');
      const banner = document.getElementById('whatif-banner');
      const badge = document.getElementById('ui-mode-badge');
      if (uiMode === 'live') {
        uiMode = 'whatif';
        whatIfGraph = JSON.parse(JSON.stringify(liveGraph));
        baselineSim = simulate(whatIfGraph, customEntryId);
        btn.textContent = '🔴 Exit What-If';
        banner.style.display = 'block';
        badge.className = 'badge mode-whatif';
        badge.textContent = 'UI MODE: WHAT-IF';
        setDefenseTool('scissors');
      } else {
        uiMode = 'live';
        whatIfGraph = null;
        baselineSim = null;
        setDefenseTool(null);
        btn.textContent = '🛡️ What-If Mode';
        banner.style.display = 'none';
        badge.className = 'badge mode-live';
        badge.textContent = 'UI MODE: LIVE';
      }
      render();
    }

    function setDefenseTool(tool) {
      activeTool = activeTool === tool ? null : tool;
      document.getElementById('tool-scissors').classList.toggle('active-tool', activeTool === 'scissors');
      document.getElementById('tool-patch').classList.toggle('active-tool', activeTool === 'patch');
      const hint = document.getElementById('map-hint');
      if (activeTool === 'scissors') hint.textContent = '✂️ SCISSORS ACTIVE: Click any edge on the map to firewall/sever it!';
      else if (activeTool === 'patch') hint.textContent = '🩹 PATCH ACTIVE: Click any node on the map to clear its CVEs!';
      else hint.textContent = 'Click any node to inspect & trigger outbreak!';
    }

    function onEdgeClick(edgeId) {
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const e = whatIfGraph.edges.find(ed => ed.id === edgeId);
      if (e) {
        e.status = e.status === 'firewalled' ? 'open' : 'firewalled';
        logMsg('WHAT-IF FIREWALL EDGE (B6)', { edgeId, status: e.status });
        render();
        const g = getActiveGraph();
        const curr = g.nodes.find(n => n.id === selectedNodeId);
        if (curr) renderNodeInspector(curr);
        refreshWizInsights();
      }
    }

    function onNodeClick(nodeId) {
      const g = getActiveGraph();
      const node = g.nodes.find(nd => nd.id === nodeId);
      if (!node) return;

      selectedNodeId = nodeId;
      renderNodeInspector(node);
      switchInspectorTab('inspector');

      if (uiMode === 'whatif' && activeTool === 'patch') {
        node.vulnerabilities = [];
        node.cvss_score = 0;
        logMsg('WHAT-IF PATCH NODE', { nodeId, vulnerabilities: [] });
        render();
        renderNodeInspector(node);
        refreshWizInsights();
        return;
      }

      customEntryId = nodeId;
      render();
      refreshWizInsights();
      logMsg('NODE SELECTED FOR INSPECTOR', { nodeId, label: node.label, type: node.type, cvss: node.cvss_score });
    }

    async function applyOptimalFix() {
      await toggleChokepointFix();
    }

    function deployDecoyAction() {
      if (uiMode !== 'whatif') toggleWhatIfMode();
      const sim = simulate(whatIfGraph, customEntryId);
      const decoyId = 'decoy-honeypot-' + Date.now().toString().slice(-4);
      whatIfGraph.nodes.push({
        id: decoyId,
        label: 'Decoy Honeypot (Active)',
        type: 'Decoy',
        cvss_score: 10,
        vulnerabilities: ['CVE-HONEYPOT-BAIT'],
        is_crown_jewel: false,
        is_decoy: true,
        status: 'secure',
        pos: { x: 560, y: 490 }
      });
      const sources = sim.path.length > 1 ? sim.path.slice(0, sim.path.length - 1) : whatIfGraph.nodes.slice(0, 2).map(n => n.id);
      sources.forEach(srcId => {
        whatIfGraph.edges.push({
          id: `e-decoy-${srcId}-${decoyId}`,
          source: srcId,
          target: decoyId,
          protocol: 'SSH',
          exploit_time_sec: 0.5,
          status: 'open'
        });
      });
      logMsg('WHAT-IF DEPLOY DECOY (B6)', { decoyId, connectedFrom: sources });
      render();
    }

    function applyEventToGraph(target, ev) {
      const t = ev.type, p = ev.payload || {};
      if (t === 'node_added') {
        if (!target.nodes.some(n => n.id === ev.id)) target.nodes.push({ ...p, id: ev.id });
      } else if (t === 'node_removed') {
        target.nodes = target.nodes.filter(n => n.id !== ev.id);
      } else if (t === 'node_updated' || t === 'node_compromised') {
        const node = target.nodes.find(n => n.id === ev.id);
        if (node) {
          if (t === 'node_compromised') node.status = 'compromised';
          Object.assign(node, p);
        }
      } else if (t === 'cve_found') {
        const node = target.nodes.find(n => n.id === ev.id);
        if (node) {
          node.vulnerabilities = Array.from(new Set([...(node.vulnerabilities || []), ...(p.vulnerabilities || [])]));
          if (p.cvss_score !== undefined) node.cvss_score = p.cvss_score;
        }
      } else if (t === 'edge_added') {
        if (!target.edges.some(e => e.id === ev.id)) target.edges.push({ ...p, id: ev.id });
      } else if (t === 'edge_removed') {
        target.edges = target.edges.filter(e => e.id !== ev.id);
      } else if (t === 'edge_updated' || t === 'edge_active_attack') {
        const edge = target.edges.find(e => e.id === ev.id);
        if (edge) {
          if (t === 'edge_active_attack') edge.status = 'active_attack';
          Object.assign(edge, p);
        }
      }
    }

    function connect() {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const host = location.host && location.host.includes(':') ? location.host : 'localhost:8000';
      const wsUrl = `${proto}://${host}/ws`;
      const badge = document.getElementById('badge');

      ws = new WebSocket(wsUrl);
      ws.onopen = async () => {
        badge.className = 'badge status-connected';
        badge.textContent = `Connected: ${wsUrl}`;
        const h = await (await fetch('/health')).json();
        currentSourceMode = h.source_mode;
        document.getElementById('mode-badge').textContent = `SOURCE: ${currentSourceMode}`;
        await refreshWizInsights();
      };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        logMsg(`RECV [${msg.kind}]`, msg);
        if (msg.kind === 'snapshot') {
          liveGraph = msg.graph || { nodes: [], edges: [] };
          if (!selectedNodeId && liveGraph.nodes.length > 0) {
            const initNode = liveGraph.nodes.find(n => n.type === 'Workstation' || n.type === 'IoT') || liveGraph.nodes[0];
            if (initNode) {
              selectedNodeId = initNode.id;
              renderNodeInspector(initNode);
            }
          }
          refreshWizInsights();
        } else if (msg.kind === 'event' && msg.event) {
          applyEventToGraph(liveGraph, msg.event);
          if (selectedNodeId) {
            const curr = (getActiveGraph().nodes || []).find(n => n.id === selectedNodeId);
            if (curr) renderNodeInspector(curr);
          }
        }
        render();
      };
      ws.onclose = () => {
        badge.className = 'badge status-disconnected';
        badge.textContent = 'Disconnected (retrying...)';
        setTimeout(connect, 2500);
      };
    }

    function sendCtrl(action, speed, entry) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      if (uiMode === 'whatif' && action === 'start') toggleWhatIfMode();
      const msg = { kind: 'replay_control', action, speed, entry };
      ws.send(JSON.stringify(msg));
      logMsg('SENT replay_control', msg);
    }

    function startOutbreak(speed) {
      const g = getActiveGraph();
      const entryNode = g.nodes.find(n => n.type === 'IoT' || n.type === 'Workstation') || g.nodes[0];
      customEntryId = entryNode ? entryNode.id : null;
      sendCtrl('start', speed, customEntryId);
    }

    async function triggerCloudPoll() {
      const res = await fetch('/cloud/poll', { method: 'POST' });
      logMsg('REAL INFRASTRUCTURE SCAN (A4)', await res.json());
      await refreshWizInsights();
    }

    async function toggleSourceMode() {
      const next = currentSourceMode === 'replay' ? 'live' : 'replay';
      const res = await fetch('/config/source', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: next })
      });
      const data = await res.json();
      currentSourceMode = data.source_mode;
      document.getElementById('mode-badge').textContent = `SOURCE: ${currentSourceMode}`;
      logMsg('MODE SWITCH (A7)', data);
      await refreshWizInsights();
    }

    connect();
  