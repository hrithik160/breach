import { create } from 'zustand';
import {
  GEdge,
  GNode,
  Graph,
  GraphEvent,
  ScorecardData,
  ScorecardMetrics,
  SimResult,
} from '../../../shared/types';
import { simulate } from '../engine/simulate';

export type SimulationMode = 'live' | 'whatif';
export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';
export type ActiveTool = 'select' | 'scissors' | 'patch' | null;

export interface ScorecardDisplayMetrics {
  blastRadius: { compromised: number; total: number };
  timeToCrownSec: number | null;
  riskScore: number;
  reachedCrownJewel: boolean;
}

export interface GraphStoreState {
  // Graph state
  mode: SimulationMode;
  liveGraph: Graph;
  whatIfGraph: Graph | null;
  graph: Graph; // Current active graph to render
  entryNodeIds: string[];

  // Simulation results
  sim: SimResult;
  baselineSim: SimResult | null;
  scorecard: ScorecardData | null;

  // Connection & UI Tool State
  connectionState: ConnectionState;
  connected: boolean;
  activeTool: ActiveTool;
  playbackStep: number | null;
  selectedNodeId: string | null;
  sourceMode: 'replay' | 'live';
  wireLogs: string[];
  wizAnalysis: any | null;
  isScanning: boolean;
  isAttacking: boolean;
  activeInspectorTab: 'asset' | 'wiz' | 'wire' | 'lab';
  lastAttackResult: any | null;

  // Actions
  applySnapshot: (snapshot: Graph) => void;
  applyEvent: (event: GraphEvent) => void;
  setMode: (mode: SimulationMode) => void;
  setEntryNodes: (nodeIds: string[]) => void;
  setActiveTool: (tool: ActiveTool) => void;
  setPlaybackStep: (step: number | null) => void;
  selectNode: (nodeId: string | null) => void;
  setActiveInspectorTab: (tab: 'asset' | 'wiz' | 'wire' | 'lab') => void;
  setConnectionState: (state: ConnectionState) => void;
  appendWireLog: (raw: string) => void;
  clearWireLogs: () => void;
  getActiveGraph: () => Graph;
  getScorecard: () => { baseline: ScorecardDisplayMetrics; current: ScorecardDisplayMetrics };

  // Sandbox & Defense Actions
  fork: () => void;
  resetWhatIf: () => void;
  firewallEdge: (edgeId: string) => void;
  patchNode: (nodeId: string) => void;
  deployDecoy: (targetNodeId?: string | unknown) => void;
  autoShieldChokePoint: () => Promise<string | null>;
  isSimRunning: boolean;
  simSpeed: number;
  startWhatIfSim: (speed?: number) => void;
  pauseWhatIfSim: () => void;
  resetWhatIfSim: () => void;

  // Interactive Architecture & Cyber Security Sandbox Operations
  selectedEdgeId: string | null;
  selectEdge: (edgeId: string | null) => void;
  isAddNodeModalOpen: boolean;
  setIsAddNodeModalOpen: (isOpen: boolean) => void;
  updateNodePosition: (nodeId: string, pos: { x: number; y: number }) => void;
  addWhatIfNode: (node: Partial<GNode>) => GNode;
  addWhatIfEdge: (source: string, target: string, protocol?: string, exploitTime?: number) => GEdge | null;
  removeWhatIfNode: (nodeId: string) => void;
  removeWhatIfEdge: (edgeId: string) => void;
  isolateNode: (nodeId: string) => void;
  setNodeStatus: (nodeId: string, status: 'secure' | 'compromised' | 'isolated') => void;
  toggleCrownJewel: (nodeId: string) => void;
  updateEdgeProtocol: (edgeId: string, protocol: 'SSH' | 'HTTPS' | 'SMB' | 'IAM_Trust' | 'Telnet') => void;

  // Real-world Infrastructure & Backend Integrations
  fetchWizAnalysis: () => Promise<any>;
  scanRealInfrastructure: () => Promise<any>;
  scanWebsiteTopology: () => Promise<any>;
  switchTopologyMode: (topType: 'website' | 'cloud' | 'host') => Promise<any>;
  currentTopologyType: 'website' | 'cloud' | 'host';
  triggerAttack: (vector?: string, input?: string, target?: string) => Promise<any>;
  setSourceMode: (src: 'replay' | 'live') => Promise<void>;
  recomputeSim: (immediate?: boolean) => void;
}

const emptySim: SimResult = {
  reachedCrownJewel: false,
  path: [],
  edgesUsed: [],
  timeline: [],
  blastRadius: { compromised: 0, total: 0 },
  timeToCrownSec: null,
};

export function calculateRiskScore(sim: SimResult): number {
  if (sim.blastRadius.total === 0 || sim.blastRadius.compromised === 0) {
    return 0;
  }

  const blastRatio = sim.blastRadius.compromised / sim.blastRadius.total;

  if (sim.reachedCrownJewel) {
    const timeFactor =
      sim.timeToCrownSec !== null
        ? Math.max(0, 30 - Math.min(sim.timeToCrownSec, 30)) * 1.0
        : 10;
    const score = 50 + blastRatio * 20 + timeFactor;
    return Math.min(100, Math.round(score));
  } else {
    const score = blastRatio * 45;
    return Math.min(45, Math.round(score));
  }
}

export function computeScorecard(baseline: SimResult, current: SimResult): ScorecardData {
  const beforeRisk = calculateRiskScore(baseline);
  const afterRisk = calculateRiskScore(current);

  const before: ScorecardMetrics = {
    compromisedCount: baseline.blastRadius.compromised,
    totalCount: baseline.blastRadius.total,
    blastRadiusRatio:
      baseline.blastRadius.total > 0
        ? baseline.blastRadius.compromised / baseline.blastRadius.total
        : 0,
    timeToCrownSec: baseline.timeToCrownSec,
    reachedCrownJewel: baseline.reachedCrownJewel,
    riskScore: beforeRisk,
  };

  const after: ScorecardMetrics = {
    compromisedCount: current.blastRadius.compromised,
    totalCount: current.blastRadius.total,
    blastRadiusRatio:
      current.blastRadius.total > 0
        ? current.blastRadius.compromised / current.blastRadius.total
        : 0,
    timeToCrownSec: current.timeToCrownSec,
    reachedCrownJewel: current.reachedCrownJewel,
    riskScore: afterRisk,
  };

  const timeDelaySec =
    after.timeToCrownSec !== null && before.timeToCrownSec !== null
      ? Math.round((after.timeToCrownSec - before.timeToCrownSec) * 10) / 10
      : null;

  return {
    before,
    after,
    blastRadiusReduction: Math.max(0, before.compromisedCount - after.compromisedCount),
    timeDelaySec,
    riskScoreReduction: Math.max(0, beforeRisk - afterRisk),
  };
}

function runSimulateWithFallback(graph: Graph, entryNodeIds: string[]): SimResult {
  const opts = entryNodeIds.length > 0 ? { entry: entryNodeIds } : undefined;
  return simulate(graph, opts);
}

function applyEventToGraph(target: Graph, event: GraphEvent): void {
  switch (event.type) {
    case 'node_added': {
      if (event.payload && 'label' in event.payload) {
        const newNode: GNode = {
          ...(event.payload as GNode),
          id: event.id,
        };
        const exists = target.nodes.some((n) => n.id === event.id);
        if (!exists) {
          target.nodes.push(newNode);
        }
      }
      break;
    }
    case 'node_removed': {
      target.nodes = target.nodes.filter((n) => n.id !== event.id);
      target.edges = target.edges.filter(
        (e) => e.source !== event.id && e.target !== event.id
      );
      break;
    }
    case 'node_updated':
    case 'node_compromised': {
      const node = target.nodes.find((n) => n.id === event.id);
      if (node) {
        if (event.type === 'node_compromised') {
          node.status = 'compromised';
        }
        if (event.payload) {
          Object.assign(node, event.payload);
        }
        if (event.source) {
          node.lastSource = event.source;
        }
      }
      break;
    }
    case 'cve_found': {
      const node = target.nodes.find((n) => n.id === event.id);
      if (node && event.payload) {
        const incoming = (event.payload as Partial<GNode>).vulnerabilities ?? [];
        node.vulnerabilities = Array.from(
          new Set([...(node.vulnerabilities ?? []), ...incoming])
        );
        if (typeof (event.payload as Partial<GNode>).cvss_score === 'number') {
          node.cvss_score = (event.payload as Partial<GNode>).cvss_score!;
        }
        if (event.source) {
          node.lastSource = event.source;
        }
      }
      break;
    }
    case 'edge_added': {
      if (event.payload && 'source' in event.payload) {
        const newEdge: GEdge = {
          ...(event.payload as GEdge),
          id: event.id,
        };
        const exists = target.edges.some((e) => e.id === event.id);
        if (!exists) {
          target.edges.push(newEdge);
        }
      }
      break;
    }
    case 'edge_removed': {
      target.edges = target.edges.filter((e) => e.id !== event.id);
      break;
    }
    case 'edge_updated':
    case 'edge_active_attack': {
      const edge = target.edges.find((e) => e.id === event.id);
      if (edge) {
        if (event.type === 'edge_active_attack') {
          edge.status = 'active_attack';
        }
        if (event.payload) {
          Object.assign(edge, event.payload);
        }
      }
      break;
    }
  }
}

let recomputeTimer: ReturnType<typeof setTimeout> | null = null;
let whatIfSimTimer: ReturnType<typeof setInterval> | null = null;

export const useGraphStore = create<GraphStoreState>((set, get) => ({
  mode: 'live',
  liveGraph: { nodes: [], edges: [] },
  whatIfGraph: null,
  graph: { nodes: [], edges: [] },
  entryNodeIds: [],
  sim: emptySim,
  baselineSim: null,
  scorecard: null,
  connectionState: 'disconnected',
  connected: false,
  activeTool: null,
  playbackStep: null,
  selectedNodeId: null,
  activeInspectorTab: 'asset',
  lastAttackResult: null,
  currentTopologyType: 'website',
  sourceMode: 'replay',
  wireLogs: [],
  wizAnalysis: null,
  isScanning: false,
  isAttacking: false,
  isSimRunning: false,
  simSpeed: 1,
  selectedEdgeId: null,
  selectEdge: (selectedEdgeId) =>
    set({
      selectedEdgeId,
      selectedNodeId: selectedEdgeId ? null : get().selectedNodeId,
      activeInspectorTab: selectedEdgeId ? 'asset' : get().activeInspectorTab,
    }),
  isAddNodeModalOpen: false,
  setIsAddNodeModalOpen: (isAddNodeModalOpen) => set({ isAddNodeModalOpen }),

  setConnectionState: (connectionState) =>
    set({
      connectionState,
      connected: connectionState === 'connected',
    }),

  setActiveTool: (activeTool) => set({ activeTool }),
  setPlaybackStep: (playbackStep) => set({ playbackStep }),
  selectNode: (selectedNodeId) =>
    set({
      selectedNodeId,
      activeInspectorTab: selectedNodeId ? 'asset' : get().activeInspectorTab,
    }),
  setActiveInspectorTab: (activeInspectorTab) => set({ activeInspectorTab }),

  appendWireLog: (raw: string) => {
    set((state) => ({
      wireLogs: [raw, ...state.wireLogs.slice(0, 99)],
    }));
  },

  clearWireLogs: () => set({ wireLogs: [] }),

  setEntryNodes: (entryNodeIds: string[]) => {
    set({ entryNodeIds });
    get().recomputeSim(true);
  },

  getActiveGraph: () => {
    const { mode, liveGraph, whatIfGraph } = get();
    return mode === 'live' ? liveGraph : whatIfGraph || liveGraph;
  },

  getScorecard: () => {
    const { baselineSim, sim } = get();
    const base = baselineSim || sim;
    return {
      baseline: {
        blastRadius: {
          compromised: base.blastRadius.compromised,
          total: base.blastRadius.total,
        },
        timeToCrownSec: base.timeToCrownSec,
        riskScore: calculateRiskScore(base),
        reachedCrownJewel: base.reachedCrownJewel,
      },
      current: {
        blastRadius: {
          compromised: sim.blastRadius.compromised,
          total: sim.blastRadius.total,
        },
        timeToCrownSec: sim.timeToCrownSec,
        riskScore: calculateRiskScore(sim),
        reachedCrownJewel: sim.reachedCrownJewel,
      },
    };
  },

  recomputeSim: (immediate = false) => {
    const run = () => {
      const { mode, liveGraph, whatIfGraph, baselineSim, entryNodeIds } = get();
      const currentActiveGraph = mode === 'whatif' && whatIfGraph ? whatIfGraph : liveGraph;
      const sim = runSimulateWithFallback(currentActiveGraph, entryNodeIds);

      let scorecard: ScorecardData | null = null;
      if (mode === 'whatif' && baselineSim) {
        scorecard = computeScorecard(baselineSim, sim);
      }

      set({
        graph: currentActiveGraph,
        sim,
        scorecard,
      });
    };

    if (immediate) {
      if (recomputeTimer) {
        clearTimeout(recomputeTimer);
        recomputeTimer = null;
      }
      run();
    } else {
      if (recomputeTimer) {
        clearTimeout(recomputeTimer);
      }
      recomputeTimer = setTimeout(() => {
        run();
        recomputeTimer = null;
      }, 200);
    }
  },

  applySnapshot: (snapshot: Graph) => {
    const liveCopy = structuredClone(snapshot);
    const { mode, whatIfGraph, entryNodeIds } = get();

    if (mode === 'live') {
      const sim = runSimulateWithFallback(liveCopy, entryNodeIds);
      set({
        liveGraph: liveCopy,
        graph: liveCopy,
        sim,
      });
    } else {
      set({ liveGraph: liveCopy });
      if (whatIfGraph) {
        get().recomputeSim(false);
      }
    }
  },

  applyEvent: (event: GraphEvent) => {
    const { mode, liveGraph } = get();
    const nextLive = structuredClone(liveGraph);
    applyEventToGraph(nextLive, event);

    if (mode === 'live') {
      set({
        liveGraph: nextLive,
        graph: nextLive,
      });
      get().recomputeSim(false);
    } else {
      set({ liveGraph: nextLive });
    }
  },

  setMode: (mode: SimulationMode) => {
    if (mode === get().mode) return;

    if (mode === 'whatif') {
      get().fork();
    } else {
      const { liveGraph, entryNodeIds } = get();
      const sim = runSimulateWithFallback(liveGraph, entryNodeIds);
      set({
        mode: 'live',
        graph: liveGraph,
        whatIfGraph: null,
        baselineSim: null,
        scorecard: null,
        sim,
        activeTool: null,
      });
    }
  },

  fork: () => {
    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    const { liveGraph, entryNodeIds } = get();
    const clonedGraph = structuredClone(liveGraph);
    const baselineSim = runSimulateWithFallback(clonedGraph, entryNodeIds);

    set({
      mode: 'whatif',
      whatIfGraph: clonedGraph,
      graph: clonedGraph,
      sim: baselineSim,
      baselineSim,
      scorecard: computeScorecard(baselineSim, baselineSim),
      playbackStep: null,
      isSimRunning: false,
    });
  },

  resetWhatIf: () => {
    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    const { liveGraph, entryNodeIds } = get();
    const clonedGraph = structuredClone(liveGraph);
    const baselineSim = runSimulateWithFallback(clonedGraph, entryNodeIds);

    set({
      whatIfGraph: clonedGraph,
      graph: clonedGraph,
      baselineSim,
      sim: baselineSim,
      scorecard: computeScorecard(baselineSim, baselineSim),
      playbackStep: null,
      isSimRunning: false,
    });
  },

  firewallEdge: (edgeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const edge = nextWhatIf.edges.find((e) => e.id === edgeId);
    if (edge) {
      edge.status = 'firewalled';
    }

    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  updateNodePosition: (nodeId: string, pos: { x: number; y: number }) => {
    const { mode, whatIfGraph, liveGraph } = get();
    if (mode === 'whatif' && whatIfGraph) {
      const nextWhatIf = structuredClone(whatIfGraph);
      const node = nextWhatIf.nodes.find((n) => n.id === nodeId);
      if (node) {
        node.pos = pos;
        set({ whatIfGraph: nextWhatIf, graph: nextWhatIf });
      }
    } else {
      const nextLive = structuredClone(liveGraph);
      const node = nextLive.nodes.find((n) => n.id === nodeId);
      if (node) {
        node.pos = pos;
        set({ liveGraph: nextLive, graph: nextLive });
      }
    }
  },

  addWhatIfNode: (newNodeData: Partial<GNode>) => {
    const { mode, whatIfGraph, liveGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) {
      get().setMode('whatif');
    }
    const currentWhatIf = get().whatIfGraph || structuredClone(liveGraph);
    const nextWhatIf = structuredClone(currentWhatIf);

    const nodeId = newNodeData.id || `custom-node-${Date.now()}`;
    const node: GNode = {
      id: nodeId,
      label: newNodeData.label || 'Custom Security Asset',
      type: newNodeData.type || 'Server',
      cvss_score: typeof newNodeData.cvss_score === 'number' ? newNodeData.cvss_score : 5.0,
      vulnerabilities: newNodeData.vulnerabilities || [],
      is_crown_jewel: Boolean(newNodeData.is_crown_jewel),
      is_decoy: Boolean(newNodeData.is_decoy),
      status: newNodeData.status || 'secure',
      pos: newNodeData.pos || { x: 420 + Math.floor(Math.random() * 120), y: 180 + Math.floor(Math.random() * 150) },
      refs: newNodeData.refs || { ip: `10.0.${Math.floor(Math.random() * 100)}.${Math.floor(Math.random() * 200)}` },
    };

    nextWhatIf.nodes.push(node);
    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
      selectedNodeId: nodeId,
      activeInspectorTab: 'asset',
    });
    return node;
  },

  addWhatIfEdge: (source: string, target: string, protocol = 'HTTPS', exploitTime = 2.0) => {
    const { mode, whatIfGraph, liveGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) {
      get().setMode('whatif');
    }
    const currentWhatIf = get().whatIfGraph || structuredClone(liveGraph);
    const nextWhatIf = structuredClone(currentWhatIf);

    // Prevent self-loop and duplicate edges
    if (source === target) return null;
    const exists = nextWhatIf.edges.some(
      (e) => (e.source === source && e.target === target) || (e.source === target && e.target === source)
    );
    if (exists) return null;

    const edgeId = `e-${source}-${target}-${Date.now()}`;
    const newEdge: GEdge = {
      id: edgeId,
      source,
      target,
      protocol: protocol as any,
      exploit_time_sec: exploitTime,
      status: 'open',
    };

    nextWhatIf.edges.push(newEdge);
    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
      selectedEdgeId: edgeId,
      activeInspectorTab: 'asset',
    });
    return newEdge;
  },

  removeWhatIfNode: (nodeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    nextWhatIf.nodes = nextWhatIf.nodes.filter((n) => n.id !== nodeId);
    nextWhatIf.edges = nextWhatIf.edges.filter((e) => e.source !== nodeId && e.target !== nodeId);

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      selectedNodeId: null,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  removeWhatIfEdge: (edgeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    nextWhatIf.edges = nextWhatIf.edges.filter((e) => e.id !== edgeId);

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      selectedEdgeId: null,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  isolateNode: (nodeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const node = nextWhatIf.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.status = node.status === 'isolated' ? 'secure' : 'isolated';
    }

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  setNodeStatus: (nodeId: string, status: 'secure' | 'compromised' | 'isolated') => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const node = nextWhatIf.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.status = status;
    }

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  toggleCrownJewel: (nodeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const node = nextWhatIf.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.is_crown_jewel = !node.is_crown_jewel;
    }

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  updateEdgeProtocol: (edgeId: string, protocol: 'SSH' | 'HTTPS' | 'SMB' | 'IAM_Trust' | 'Telnet') => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const edge = nextWhatIf.edges.find((e) => e.id === edgeId);
    if (edge) {
      edge.protocol = protocol;
    }

    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  patchNode: (nodeId: string) => {
    const { mode, whatIfGraph, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) return;

    const nextWhatIf = structuredClone(whatIfGraph);
    const node = nextWhatIf.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.vulnerabilities = [];
      node.cvss_score = 0;
    }

    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  deployDecoy: (targetNodeId?: string | unknown) => {
    const { mode, whatIfGraph, sim, baselineSim, entryNodeIds } = get();
    if (mode !== 'whatif' || !whatIfGraph) {
      get().setMode('whatif');
    }

    const currentWhatIf = get().whatIfGraph || structuredClone(get().liveGraph);
    const nextWhatIf = structuredClone(currentWhatIf);
    const decoyId = `decoy-honeypot-${Date.now()}`;

    const targetIdStr = typeof targetNodeId === 'string' ? targetNodeId : undefined;

    let x = 600;
    let y = 300;
    if (targetIdStr) {
      const refNode = nextWhatIf.nodes.find((n) => n.id === targetIdStr);
      if (refNode && refNode.pos) {
        x = refNode.pos.x + 80;
        y = refNode.pos.y + 80;
      }
    }

    const decoyNode: GNode = {
      id: decoyId,
      label: 'Decoy Honeypot (Active)',
      type: 'Decoy',
      cvss_score: 10,
      vulnerabilities: ['CVE-HONEYPOT-BAIT'],
      is_crown_jewel: false,
      is_decoy: true,
      status: 'secure',
      pos: { x, y },
    };

    nextWhatIf.nodes.push(decoyNode);

    const targetObj = targetIdStr ? nextWhatIf.nodes.find((n) => n.id === targetIdStr) : undefined;
    const sourceCandidates =
      targetIdStr && !targetObj?.is_crown_jewel
        ? [targetIdStr]
        : sim.path.length > 1
        ? sim.path.slice(0, sim.path.length - 1)
        : nextWhatIf.nodes
            .filter((n) => n.status === 'compromised' || !n.is_crown_jewel)
            .map((n) => n.id)
            .slice(0, 3);

    for (const srcId of sourceCandidates) {
      const edgeId = `e-decoy-${srcId}-${decoyId}`;
      const decoyEdge: GEdge = {
        id: edgeId,
        source: srcId,
        target: decoyId,
        protocol: 'SSH',
        exploit_time_sec: 0.5,
        status: 'open',
      };
      nextWhatIf.edges.push(decoyEdge);
    }

    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    const nextSim = runSimulateWithFallback(nextWhatIf, entryNodeIds);
    const scorecard = baselineSim ? computeScorecard(baselineSim, nextSim) : null;

    set({
      mode: 'whatif',
      whatIfGraph: nextWhatIf,
      graph: nextWhatIf,
      sim: nextSim,
      scorecard,
      playbackStep: null,
      isSimRunning: false,
    });
  },

  startWhatIfSim: (speed = 1) => {
    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }

    const { sim, playbackStep } = get();
    if (!sim || sim.timeline.length === 0) return;

    let current = playbackStep;
    if (current === null || current >= sim.timeline.length - 1) {
      current = 0;
      set({ playbackStep: 0 });
    }

    set({ isSimRunning: true, simSpeed: speed });

    const stepIntervalMs = Math.round(1100 / speed);

    whatIfSimTimer = setInterval(() => {
      const state = get();
      if (!state.isSimRunning) {
        if (whatIfSimTimer) clearInterval(whatIfSimTimer);
        whatIfSimTimer = null;
        return;
      }

      const next = (state.playbackStep === null ? 0 : state.playbackStep) + 1;
      if (next < state.sim.timeline.length) {
        set({ playbackStep: next });
      } else {
        if (whatIfSimTimer) {
          clearInterval(whatIfSimTimer);
          whatIfSimTimer = null;
        }
        set({ isSimRunning: false });
      }
    }, stepIntervalMs);
  },

  pauseWhatIfSim: () => {
    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    set({ isSimRunning: false });
  },

  resetWhatIfSim: () => {
    if (whatIfSimTimer) {
      clearInterval(whatIfSimTimer);
      whatIfSimTimer = null;
    }
    set({ isSimRunning: false, playbackStep: null });
  },

  autoShieldChokePoint: async () => {
    // Ensure in What-If mode
    if (get().mode !== 'whatif') {
      get().setMode('whatif');
    }

    try {
      const resp = await fetch('http://localhost:8000/wiz/analysis');
      if (resp.ok) {
        const data = await resp.json();
        set({ wizAnalysis: data });
        if (data.optimal_chokepoint?.edge_id) {
          const edgeId = data.optimal_chokepoint.edge_id;
          get().firewallEdge(edgeId);
          return edgeId;
        }
      }
    } catch (e) {
      console.warn('Backend /wiz/analysis not reachable, computing choke point client-side', e);
    }

    // Client-side fallback choke point optimizer
    const { whatIfGraph, baselineSim, entryNodeIds } = get();
    if (!whatIfGraph) return null;

    const baseSim = runSimulateWithFallback(whatIfGraph, entryNodeIds);
    let bestEdgeId: string | null = null;
    let maxSaved = -1;

    for (const eid of baseSim.edgesUsed) {
      const testGraph = structuredClone(whatIfGraph);
      const testEdge = testGraph.edges.find((e) => e.id === eid);
      if (testEdge) testEdge.status = 'firewalled';
      const sim = runSimulateWithFallback(testGraph, entryNodeIds);
      const saved = baseSim.blastRadius.compromised - sim.blastRadius.compromised;
      const crownProtected = baseSim.reachedCrownJewel && !sim.reachedCrownJewel;
      const score = (crownProtected ? 100 : 0) + saved * 5;
      if (score > maxSaved) {
        maxSaved = score;
        bestEdgeId = eid;
      }
    }

    if (bestEdgeId) {
      get().firewallEdge(bestEdgeId);
      return bestEdgeId;
    }

    return null;
  },

  fetchWizAnalysis: async () => {
    try {
      const resp = await fetch('http://localhost:8000/wiz/analysis');
      if (resp.ok) {
        const data = await resp.json();
        set({ wizAnalysis: data });
        return data;
      }
    } catch (e) {
      console.warn('Failed to fetch wiz analysis:', e);
    }
    return null;
  },

  scanRealInfrastructure: async () => {
    set({ isScanning: true });
    try {
      const resp = await fetch('http://localhost:8000/cloud/poll', { method: 'POST' });
      const data = await resp.json();
      set({ currentTopologyType: 'host' });
      return data;
    } catch (e) {
      console.error('Scan failed:', e);
    } finally {
      set({ isScanning: false });
    }
  },

  scanWebsiteTopology: async () => {
    set({ isScanning: true });
    try {
      const resp = await fetch('http://localhost:8000/api/site/scan', { method: 'POST' });
      const data = await resp.json();
      set({ currentTopologyType: 'website' });
      return data;
    } catch (e) {
      console.error('Website scan failed:', e);
    } finally {
      set({ isScanning: false });
    }
  },

  switchTopologyMode: async (topType: 'website' | 'cloud' | 'host') => {
    try {
      await fetch('http://localhost:8000/config/topology', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topology: topType }),
      });
      set({ currentTopologyType: topType });
    } catch (e) {
      console.error('Topology switch failed:', e);
    }
  },

  triggerAttack: async (vector = 'sqli', input = "admin' OR 1=1 --", target = '') => {
    set({ isAttacking: true });
    try {
      // If user is in What-If Sandbox mode, immediately kick off the simulated hack outbreak so the graph animates!
      if (get().mode === 'whatif') {
        get().startWhatIfSim(1.5);
      }

      const resp = await fetch('http://localhost:8000/portal/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vector, input, target_node: target }),
      });
      const data = await resp.json();
      set({ lastAttackResult: data });
      return data;
    } catch (e) {
      console.error('Attack trigger failed:', e);
    } finally {
      set({ isAttacking: false });
    }
  },

  setSourceMode: async (src: 'replay' | 'live') => {
    try {
      await fetch('http://localhost:8000/config/source', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: src }),
      });
      set({ sourceMode: src });
    } catch (e) {
      console.error('Failed to change source mode:', e);
    }
  },
}));
