import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  Network,
  Cpu,
  Terminal,
  Zap,
  Check,
  Copy,
  Trash2,
  Lock,
  Flame,
  Play,
  Globe,
  Radio,
  Crown,
  ShieldCheck,
  Ban,
  Link2,
  Unlink,
  Scissors,
} from 'lucide-react';
import { useGraphStore } from '../store/graphStore';

const exploitPresets = [
  {
    id: 'sqli',
    title: 'SQL Injection',
    icon: '💉',
    payload: "admin' OR 1=1 --",
    vector: 'sqli',
    target: 'node-api-gateway',
    desc: 'Database auth bypass & dump credentials',
  },
  {
    id: 'aws',
    title: 'Leaked AWS Key',
    icon: '🔑',
    payload: 'AKIAIOSFODNN7EXAMPLEREDTEAM',
    vector: 'leaked_api_key',
    target: 'node-dev-laptop',
    desc: 'IAM dev token lateral pivot',
  },
  {
    id: 'traversal',
    title: 'Path Traversal',
    icon: '📂',
    payload: '../../../../etc/shadow',
    vector: 'path_traversal',
    target: 'node-dmz-proxy',
    desc: 'Arbitrary sensitive file disclosure',
  },
  {
    id: 'printer',
    title: 'IoT Printer Overflow',
    icon: '🖨️',
    payload: 'HP_RAW_SOCKET_BUFFER_OVERFLOW',
    vector: 'printer_overflow',
    target: 'node-printer',
    desc: 'CVE-2023-3519 buffer overflow',
  },
];

export const NodeInspector: React.FC = () => {
  const {
    selectedNodeId,
    selectNode,
    getActiveGraph,
    mode,
    setMode,
    patchNode,
    wireLogs,
    clearWireLogs,
    wizAnalysis,
    fetchWizAnalysis,
    autoShieldChokePoint,
    activeInspectorTab,
    setActiveInspectorTab,
    triggerAttack,
    isAttacking,
    lastAttackResult,
    scanWebsiteTopology,
    currentTopologyType,
    selectedEdgeId,
    selectEdge,
    removeWhatIfNode,
    removeWhatIfEdge,
    isolateNode,
    setNodeStatus,
    toggleCrownJewel,
    updateEdgeProtocol,
    firewallEdge,
  } = useGraphStore();

  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [snippetTab, setSnippetTab] = useState<'iptables' | 'aws_cli' | 'terraform' | 'k8s_cilium'>('iptables');

  // Exploit Lab Form State
  const [vector, setVector] = useState<string>('sqli');
  const [payload, setPayload] = useState<string>("admin' OR 1=1 --");
  const [targetNode, setTargetNode] = useState<string>('');
  const [showEmbeddedSite, setShowEmbeddedSite] = useState<boolean>(false);

  // Auto switch to asset tab when a node is clicked on canvas
  useEffect(() => {
    if (selectedNodeId) {
      setActiveInspectorTab('asset');
    }
  }, [selectedNodeId, setActiveInspectorTab]);

  // Fetch initial wiz analysis if not loaded
  useEffect(() => {
    if (!wizAnalysis) {
      fetchWizAnalysis();
    }
  }, [fetchWizAnalysis, wizAnalysis]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(key);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const handleApplyPreset = async (p: typeof exploitPresets[0], executeImmediate = false) => {
    setVector(p.vector);
    setPayload(p.payload);
    setTargetNode(p.target);
    if (currentTopologyType !== 'website') {
      await scanWebsiteTopology();
    }
    if (executeImmediate) {
      triggerAttack(p.vector, p.payload, p.target);
    }
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (currentTopologyType !== 'website') {
      await scanWebsiteTopology();
    }
    triggerAttack(vector, payload, targetNode);
  };

  const graph = getActiveGraph();
  const selectedNode = selectedNodeId ? graph.nodes.find((n) => n.id === selectedNodeId) : null;
  const selectedEdge = selectedEdgeId ? graph.edges.find((e) => e.id === selectedEdgeId) : null;
  const connectedEdges = selectedNode
    ? graph.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
    : [];

  const toxicCombo = wizAnalysis?.toxic_combinations?.[0];
  const chokePoint = wizAnalysis?.optimal_chokepoint;
  const remediationSnippets = wizAnalysis?.remediation_snippets || {};

  return (
    <div className="fixed top-20 right-5 z-30 w-[420px] max-h-[85vh] flex flex-col rounded-2xl bg-slate-900/95 border border-slate-700/80 p-4 backdrop-blur-md shadow-2xl overflow-hidden transition-all">
      {/* Top Header & Tab Navigation */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1 rounded-lg bg-slate-950 p-1 border border-slate-800 text-[11px]">
          <button
            onClick={() => setActiveInspectorTab('lab')}
            className={`flex items-center gap-1 px-2 py-1 rounded-md transition ${
              activeInspectorTab === 'lab'
                ? 'bg-red-950/80 text-red-300 border border-red-700/50 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-red-400" />
            Exploit Lab
          </button>

          <button
            onClick={() => setActiveInspectorTab('asset')}
            className={`flex items-center gap-1 px-2 py-1 rounded-md transition ${
              activeInspectorTab === 'asset'
                ? 'bg-slate-800 text-sky-300 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            {selectedEdge ? `Link (${selectedEdge.protocol})` : selectedNode ? `Asset (${selectedNode.label.slice(0, 7)}...)` : 'Asset'}
          </button>

          <button
            onClick={() => setActiveInspectorTab('wiz')}
            className={`flex items-center gap-1 px-2 py-1 rounded-md transition ${
              activeInspectorTab === 'wiz'
                ? 'bg-purple-900/50 text-purple-300 border border-purple-500/40 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-purple-400" />
            Wiz Intel
          </button>

          <button
            onClick={() => setActiveInspectorTab('wire')}
            className={`flex items-center gap-1 px-2 py-1 rounded-md transition ${
              activeInspectorTab === 'wire'
                ? 'bg-slate-800 text-slate-200 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            Wire ({wireLogs.length})
          </button>
        </div>

        {selectedNodeId && activeInspectorTab === 'asset' && (
          <button
            onClick={() => selectNode(null)}
            className="p-1 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            title="Deselect Node"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Tab 0: Exploit Lab (Stay on Graph & Test Website Exploits) */}
      {activeInspectorTab === 'lab' && (
        <div className="flex-1 overflow-y-auto mt-3 pr-1 space-y-3.5 text-xs">
          {/* Active Topology Indicator & Switcher */}
          <div className="flex items-center justify-between p-2.5 rounded-xl bg-sky-950/40 border border-sky-600/40 text-[11px]">
            <span className="flex items-center gap-1.5 text-sky-200 font-semibold truncate">
              <Globe className="w-3.5 h-3.5 text-sky-400 shrink-0" />
              Graph: {currentTopologyType === 'website' ? 'Website Topology (Dynamic)' : 'PC Host Topology'}
            </span>
            <button
              type="button"
              onClick={() => scanWebsiteTopology()}
              className="px-2.5 py-1 rounded bg-sky-600 hover:bg-sky-500 text-white font-bold text-[10.5px] transition shadow shrink-0"
              title="Dynamically scan and project temp website onto graph"
            >
              {currentTopologyType === 'website' ? 'Re-Scan Site' : 'Switch to Website'}
            </button>
          </div>

          {/* Header banner */}
          <div className="rounded-xl bg-slate-950 p-3 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 font-bold text-red-400 text-xs">
                <Flame className="w-4 h-4 text-red-400" /> Apex Cloud Portal Exploit Lab
              </span>
              <button
                onClick={() => setShowEmbeddedSite((v) => !v)}
                className={`text-[10px] px-2 py-0.5 rounded border transition flex items-center gap-1 ${
                  showEmbeddedSite
                    ? 'bg-sky-500/20 text-sky-300 border-sky-400/50'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                }`}
              >
                <Globe className="w-3 h-3" />
                {showEmbeddedSite ? 'Hide Web Preview' : 'Show Web Preview'}
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              Trigger real-time exploits into your network without leaving this graph. Watch domino infections propagate live.
            </p>
          </div>

          {/* Optional Embedded Iframe Preview */}
          {showEmbeddedSite && (
            <div className="rounded-xl border border-slate-700 overflow-hidden bg-slate-950">
              <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                <span>Embedded Target Site: http://localhost:8000/site/</span>
                <span className="text-emerald-400 flex items-center gap-1">● Synced</span>
              </div>
              <iframe
                src="http://localhost:8000/site/"
                title="Apex Cloud Target Site"
                className="w-full h-64 border-0"
              />
            </div>
          )}

          {/* 1-Click Exploit Presets */}
          <div className="space-y-2">
            <span className="text-[11px] font-semibold text-slate-300 flex items-center gap-1">
              ⚡ 1-Click Exploit Presets:
            </span>
            <div className="grid grid-cols-2 gap-2">
              {exploitPresets.map((p) => (
                <div
                  key={p.id}
                  onClick={() => handleApplyPreset(p, false)}
                  className={`p-2.5 rounded-xl border text-left cursor-pointer transition flex flex-col justify-between ${
                    vector === p.vector && payload === p.payload
                      ? 'bg-red-950/50 border-red-500 shadow-[0_0_12px_rgba(239,68,68,0.25)]'
                      : 'bg-slate-950/80 border-slate-800 hover:bg-slate-800/60 hover:border-slate-700'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-slate-200 text-xs flex items-center gap-1">
                        <span>{p.icon}</span> {p.title}
                      </span>
                    </div>
                    <p className="text-[10px] font-mono text-slate-400 truncate mb-1">
                      {p.payload}
                    </p>
                    <p className="text-[9.5px] text-slate-500 line-clamp-1">{p.desc}</p>
                  </div>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleApplyPreset(p, true);
                    }}
                    disabled={isAttacking}
                    className="mt-2 w-full py-1 rounded bg-red-900/60 hover:bg-red-800 text-[10.5px] font-semibold text-red-200 border border-red-700/50 flex items-center justify-center gap-1 shadow"
                  >
                    <Play className="w-2.5 h-2.5 fill-current" /> Fire Exploit
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Custom Attack Form */}
          <form onSubmit={handleFormSubmit} className="space-y-2.5 rounded-xl bg-slate-950 p-3 border border-slate-800">
            <span className="font-semibold text-slate-300 text-[11px] block">
              🛠️ Custom Attack Injector:
            </span>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Attack Vector</label>
                <select
                  value={vector}
                  onChange={(e) => setVector(e.target.value)}
                  className="w-full rounded-lg bg-slate-900 border border-slate-700 px-2 py-1.5 text-[11px] text-slate-200 font-mono focus:border-red-500 outline-none"
                >
                  <option value="sqli">SQL Injection (sqli)</option>
                  <option value="leaked_api_key">Leaked AWS Key</option>
                  <option value="path_traversal">Path Traversal</option>
                  <option value="printer_overflow">Printer Buffer Overflow</option>
                  <option value="custom">Custom Payload</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Target Asset</label>
                <select
                  value={targetNode}
                  onChange={(e) => setTargetNode(e.target.value)}
                  className="w-full rounded-lg bg-slate-900 border border-slate-700 px-2 py-1.5 text-[11px] text-slate-200 font-mono focus:border-red-500 outline-none"
                >
                  <option value="">Auto-Detect by Vector</option>
                  {graph.nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.label} ({n.type})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Payload / Exploitation String</label>
              <textarea
                rows={2}
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                placeholder="Enter SQLi, JWT token, shellcode, or traversal..."
                className="w-full rounded-lg bg-slate-900 border border-slate-700 p-2 text-[11px] text-slate-200 font-mono focus:border-red-500 outline-none resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={isAttacking}
              className="w-full py-2 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-lg transition disabled:opacity-50"
            >
              <Flame className={`w-3.5 h-3.5 ${isAttacking ? 'animate-bounce' : ''}`} />
              {isAttacking ? 'Launching Attack & Propagating...' : 'Submit Payload & Trigger Live Outbreak'}
            </button>
          </form>

          {/* Live Server Response Card */}
          {lastAttackResult && (
            <div className="rounded-xl bg-red-950/40 border border-red-600/60 p-3 space-y-2 font-mono text-[11px]">
              <div className="flex items-center justify-between text-red-300 font-bold">
                <span className="flex items-center gap-1">
                  <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" /> TARGET SERVER RESPONSE
                </span>
                <span className="px-1.5 py-0.5 rounded bg-red-500/30 text-red-200 text-[10px]">
                  BREACHED: {lastAttackResult.entry_node}
                </span>
              </div>
              <p className="text-slate-200 font-sans text-xs bg-slate-950/80 p-2 rounded border border-red-800/40">
                {lastAttackResult.simulated_server_response}
              </p>
              <div className="flex items-center justify-between text-[10px] pt-1">
                <span className="text-emerald-400 flex items-center gap-1">
                  ✓ Outbreak wave streaming on graph
                </span>
                {mode === 'whatif' ? (
                  <button
                    type="button"
                    onClick={() => setMode('live')}
                    className="px-2 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-bold transition shadow ml-2 shrink-0 font-sans text-[10.5px]"
                    title="Switch to Live Telemetry mode to watch backend WebSocket outbreak"
                  >
                    View Live Stream
                  </button>
                ) : (
                  <span className="text-slate-400 font-sans text-[10px]">Live Telemetry Active</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 1: Asset / Link Inspector */}
      {activeInspectorTab === 'asset' && (
        <div className="flex-1 overflow-y-auto mt-3 pr-1 space-y-3.5 text-xs">
          {/* Case A: Selected Edge Inspector */}
          {selectedEdge ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 flex items-center gap-1">
                  <Network className="w-3 h-3" /> Connection Link
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  selectedEdge.status === 'firewalled'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : selectedEdge.status === 'active_attack'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}>
                  {selectedEdge.status.toUpperCase()}
                </span>
              </div>

              <div className="rounded-xl bg-slate-950 p-3 border border-slate-800 space-y-1.5 font-mono text-[11px]">
                <div className="text-slate-400 font-sans font-semibold mb-1">Endpoints</div>
                <div className="truncate">Source: <span className="text-slate-200">{graph.nodes.find(n => n.id === selectedEdge.source)?.label || selectedEdge.source}</span></div>
                <div className="truncate">Target: <span className="text-slate-200">{graph.nodes.find(n => n.id === selectedEdge.target)?.label || selectedEdge.target}</span></div>
                <div>Exploit / Pivot Latency: <span className="text-amber-400 font-bold">{selectedEdge.exploit_time_sec}s</span></div>
              </div>

              {/* Protocol Configuration */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-semibold text-slate-400 block">Communication Protocol</label>
                {mode === 'whatif' ? (
                  <select
                    value={selectedEdge.protocol}
                    onChange={(e) => updateEdgeProtocol(selectedEdge.id, e.target.value as any)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
                  >
                    <option value="HTTPS">HTTPS (TLS Encrypted Web Pivot)</option>
                    <option value="SSH">SSH (Encrypted Remote Shell)</option>
                    <option value="IAM_Trust">IAM_Trust (Cloud Service AssumeRole)</option>
                    <option value="SMB">SMB (Windows File Sharing / Named Pipes)</option>
                    <option value="Telnet">Telnet (Cleartext Insecure Pivot)</option>
                  </select>
                ) : (
                  <div className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200">
                    {selectedEdge.protocol}
                  </div>
                )}
              </div>

              {/* Cyber Security Edge Operations */}
              {mode === 'whatif' && (
                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <div className="font-semibold text-slate-300 text-[11px] flex items-center gap-1">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Defense Firewall Operations
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => firewallEdge(selectedEdge.id)}
                      className={`px-3 py-2 rounded-xl border text-xs font-semibold flex items-center justify-center gap-1.5 transition ${
                        selectedEdge.status === 'firewalled'
                          ? 'bg-emerald-600/30 border-emerald-500/50 text-emerald-200 hover:bg-emerald-600/40'
                          : 'bg-red-600/30 border-red-500/50 text-red-200 hover:bg-red-600/40'
                      }`}
                    >
                      <Scissors className="w-3.5 h-3.5" />
                      {selectedEdge.status === 'firewalled' ? 'Unblock Edge' : 'Cut / Sever Edge'}
                    </button>

                    <button
                      type="button"
                      onClick={() => removeWhatIfEdge(selectedEdge.id)}
                      className="px-3 py-2 rounded-xl border border-red-800/40 bg-red-950/40 hover:bg-red-900/60 text-red-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Delete Link
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : !selectedNode ? (
            <div className="py-8 text-center text-slate-400 space-y-2">
              <Cpu className="w-8 h-8 mx-auto text-slate-600" />
              <p className="font-semibold text-slate-300">No Asset or Link Selected</p>
              <p className="text-[11px] text-slate-500 max-w-xs mx-auto">
                Click any device, server, database, or connection edge on the canvas to inspect and configure security defenses.
              </p>
            </div>
          ) : (
            <>
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-sky-500/20 text-sky-300">
                  {selectedNode.type}
                </span>
                <h3 className="mt-1.5 text-base font-bold text-slate-100">{selectedNode.label}</h3>
                <p className="text-[11px] font-mono text-slate-400">{selectedNode.id}</p>
              </div>

              {/* Telemetry Source & Status */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Telemetry Source:</span>
                <span className="px-2 py-0.5 rounded font-mono uppercase bg-slate-800 text-slate-200 border border-slate-700">
                  {selectedNode.lastSource || 'cloud'}
                </span>
              </div>

              {/* Asset Resolver Refs */}
              <div className="space-y-1.5 rounded-xl bg-slate-950 p-3 border border-slate-800 font-mono">
                <div className="flex items-center gap-1.5 text-slate-400 font-sans font-semibold mb-1">
                  <Cpu className="w-3.5 h-3.5" /> Asset Identifiers
                </div>
                <div>IP: <span className="text-slate-200">{selectedNode.refs?.ip || 'N/A'}</span></div>
                <div>Host: <span className="text-slate-200">{selectedNode.refs?.hostname || 'N/A'}</span></div>
                <div className="truncate">Cloud ID: <span className="text-slate-200">{selectedNode.refs?.cloud_id || 'N/A'}</span></div>
              </div>

              {/* Vulnerabilities (CVEs) */}
              <div>
                <div className="flex items-center justify-between font-semibold text-slate-300 mb-2">
                  <span className="flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Vulnerabilities (CVSS {selectedNode.cvss_score})
                  </span>
                  {mode === 'whatif' && selectedNode.vulnerabilities.length > 0 && (
                    <button
                      onClick={() => patchNode(selectedNode.id)}
                      className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30"
                    >
                      Patch All
                    </button>
                  )}
                </div>
                {selectedNode.vulnerabilities.length === 0 ? (
                  <div className="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/50 rounded-lg p-2">
                    Zero unpatched CVEs on this asset.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.vulnerabilities.map((cve) => (
                      <span
                        key={cve}
                        className="px-2 py-1 rounded bg-red-500/15 border border-red-500/30 text-red-300 font-mono text-[11px]"
                      >
                        {cve}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* What-If Cyber Security Asset Operations */}
              {mode === 'whatif' && (
                <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2.5">
                  <div className="font-semibold text-slate-200 text-[11px] flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Cyber Security Sandbox Controls
                    </span>
                    <span className="text-[10px] text-amber-300 font-mono">SANDBOX ACTIVE</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => patchNode(selectedNode.id)}
                      className="px-2.5 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-200 text-[11px] font-semibold flex items-center gap-1 transition"
                      title="Clear all vulnerabilities and remediate CVSS score"
                    >
                      <ShieldCheck className="w-3 h-3 text-emerald-400" />
                      Remediate CVEs
                    </button>

                    <button
                      type="button"
                      onClick={() => isolateNode(selectedNode.id)}
                      className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold flex items-center gap-1 transition ${
                        selectedNode.status === 'isolated'
                          ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-200'
                          : 'border-amber-500/40 bg-amber-950/40 text-amber-200 hover:bg-amber-900/50'
                      }`}
                      title="Quarantine host by severing dynamic routing"
                    >
                      <Ban className="w-3 h-3" />
                      {selectedNode.status === 'isolated' ? 'Re-Join Network' : 'Isolate Host'}
                    </button>

                    <button
                      type="button"
                      onClick={() => setNodeStatus(selectedNode.id, selectedNode.status === 'compromised' ? 'secure' : 'compromised')}
                      className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold flex items-center gap-1 transition ${
                        selectedNode.status === 'compromised'
                          ? 'border-red-500/60 bg-red-900/50 text-red-200'
                          : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                      title="Simulate breach entry foothold on this asset"
                    >
                      <Flame className="w-3 h-3 text-red-400" />
                      {selectedNode.status === 'compromised' ? 'Foothold Active' : 'Set as Foothold'}
                    </button>

                    <button
                      type="button"
                      onClick={() => toggleCrownJewel(selectedNode.id)}
                      className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold flex items-center gap-1 transition ${
                        selectedNode.is_crown_jewel
                          ? 'border-amber-400/60 bg-amber-500/20 text-amber-200 font-bold'
                          : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                      title="Toggle Crown Jewel High-Value target"
                    >
                      <Crown className="w-3 h-3 text-amber-400" />
                      {selectedNode.is_crown_jewel ? 'Crown Jewel' : 'Make Crown'}
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={() => removeWhatIfNode(selectedNode.id)}
                    className="w-full py-1.5 rounded-lg border border-red-800/40 bg-red-950/40 hover:bg-red-900/50 text-red-300 text-[11px] font-semibold flex items-center justify-center gap-1 transition"
                  >
                    <Trash2 className="w-3 h-3 text-red-400" /> Delete Asset from Sandbox
                  </button>
                </div>
              )}

              {/* Connected Protocols / IAM Trust */}
              <div>
                <div className="flex items-center gap-1.5 font-semibold text-slate-300 mb-2">
                  <Network className="w-3.5 h-3.5 text-sky-400" /> Lateral Pathways ({connectedEdges.length})
                </div>
                <div className="max-h-36 overflow-y-auto space-y-1 text-[11px] font-mono">
                  {connectedEdges.map((e) => (
                    <div
                      key={e.id}
                      className="flex items-center justify-between px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800"
                    >
                      <span className="truncate text-slate-300">
                        {e.source === selectedNode.id ? `→ ${e.target}` : `← ${e.source}`}
                      </span>
                      <span className="text-sky-400 ml-2">{e.protocol}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Tab 2: Wiz Toxic Combinations & DevSecOps Remediation */}
      {activeInspectorTab === 'wiz' && (
        <div className="flex-1 overflow-y-auto mt-3 pr-1 space-y-3 text-xs">
          {toxicCombo ? (
            <div className="rounded-xl bg-red-950/40 border border-red-700/60 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-bold font-mono text-red-400 text-[11px]">
                  <ShieldAlert className="w-3.5 h-3.5" /> WIZ TOXIC COMBINATION
                </span>
                <span className="px-1.5 py-0.5 rounded bg-red-500 text-slate-950 font-extrabold text-[10px]">
                  {toxicCombo.severity}
                </span>
              </div>
              <p className="font-semibold text-slate-100 text-xs leading-snug">
                {toxicCombo.title}
              </p>
              <ul className="space-y-1 font-mono text-[11px] text-slate-300 list-disc list-inside">
                {toxicCombo.factors?.map((f: string, idx: number) => (
                  <li key={idx} className="truncate">{f}</li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-400 text-center font-mono text-[11px]">
              No critical toxic combination active along current paths.
            </div>
          )}

          {/* Optimal Choke-Point Fix */}
          <div className="rounded-xl bg-purple-950/30 border border-purple-800/50 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 font-bold text-purple-300 text-[11px]">
                <Zap className="w-3.5 h-3.5 text-purple-400" /> Optimal Choke-Point Fix
              </span>
              <button
                onClick={autoShieldChokePoint}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white font-semibold text-[11px] shadow transition"
              >
                <Lock className="w-3 h-3" /> Auto-Shield
              </button>
            </div>
            {chokePoint ? (
              <p className="text-[11px] text-purple-200">
                Sever <span className="font-mono text-white font-bold">{chokePoint.edge_id}</span> ({chokePoint.protocol}: {chokePoint.source_label} → {chokePoint.target_label}) to save <span className="text-emerald-300 font-bold">{chokePoint.saved_nodes} nodes</span>.
              </p>
            ) : (
              <p className="text-[11px] text-slate-400">
                Computing min-cut choke point on active topology...
              </p>
            )}
          </div>

          {/* DevSecOps Remediation Snippets */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-300 text-[11px]">DevSecOps CLI Commands:</span>
            </div>
            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-[10px] font-mono">
              {(['iptables', 'aws_cli', 'terraform', 'k8s_cilium'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setSnippetTab(tab)}
                  className={`flex-1 py-1 rounded transition text-center uppercase ${
                    snippetTab === tab
                      ? 'bg-slate-800 text-sky-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab === 'aws_cli' ? 'AWS' : tab === 'k8s_cilium' ? 'K8s' : tab}
                </button>
              ))}
            </div>

            <div className="relative rounded-xl bg-slate-950 p-2.5 border border-slate-800 font-mono text-[10.5px]">
              <button
                onClick={() => copyToClipboard(remediationSnippets[snippetTab] || '', snippetTab)}
                className="absolute top-2 right-2 p-1 rounded bg-slate-800 text-slate-400 hover:text-white"
                title="Copy snippet"
              >
                {copiedCode === snippetTab ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
              <pre className="overflow-x-auto text-slate-300 whitespace-pre-wrap max-h-32">
                {remediationSnippets[snippetTab] || `# Ready: Select an edge or run auto-shield to generate commands.`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Live Wire Log (/ws) */}
      {activeInspectorTab === 'wire' && (
        <div className="flex-1 flex flex-col mt-3 overflow-hidden text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono text-slate-400">Recent WebSocket Wire Events</span>
            <button
              onClick={clearWireLogs}
              className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-red-400 font-mono"
            >
              <Trash2 className="w-3 h-3" /> Clear
            </button>
          </div>

          <div className="flex-1 max-h-[50vh] overflow-y-auto space-y-1.5 font-mono text-[10.5px] pr-1">
            {wireLogs.length === 0 ? (
              <div className="py-8 text-center text-slate-500">
                Listening on ws://localhost:8000/ws...
              </div>
            ) : (
              wireLogs.map((log, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 break-all"
                >
                  {log}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
